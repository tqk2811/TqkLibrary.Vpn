using System.Net;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Esp.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Exercises the whole IPsec stack in-process: a simulated responder completes IKE_SA_INIT + IKE_AUTH (PSK)
    /// with the real <see cref="IkeClient"/>, then both sides build ESP sessions from the CHILD_SA keys and
    /// exchange a protected packet. This pins the RFC 7296/4303 math without needing a live gateway.
    /// </summary>
    public class IkeAuthHandshakeTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");

        [Fact]
        public void SkPayload_RoundTrips_AndDetectsTampering()
        {
            IkeKeyMaterial keys = IkeKeyMaterial.DeriveDefault(
                Bytes(0x11, 32), Bytes(0x22, 32), Bytes(0x33, 256), Bytes(0x44, 8), Bytes(0x55, 8));
            var initiator = IkeCipher.ForInitiator(keys);
            var responder = IkeCipher.ForResponder(keys);

            var message = new IkeMessage
            {
                InitiatorSpi = Bytes(0x44, 8),
                ResponderSpi = Bytes(0x55, 8),
                ExchangeType = IkeExchangeType.Informational,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 7,
            };
            message.Payloads.Add(new NoncePayload { Nonce = Bytes(1, 24) });
            message.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.InitialContact, Array.Empty<byte>()));

            byte[] wire = initiator.EncryptMessage(message);
            IkeMessage? decoded = responder.DecryptMessage(wire);

            Assert.NotNull(decoded);
            Assert.Equal(7u, decoded!.MessageId);
            Assert.Equal(Bytes(1, 24), decoded.Find<NoncePayload>()!.Nonce);
            Assert.Equal(IkeNotifyMessageType.InitialContact, decoded.Notifies().Single().KnownType);

            wire[wire.Length - 1] ^= 0xFF; // tamper the ICV
            Assert.Null(responder.DecryptMessage(wire));
        }

        [Fact]
        public void FullHandshake_ThenEspExchange_Succeeds()
        {
            var idInitiator = new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
            var client = new IkeClient(Psk, idInitiator);
            var responder = new SimulatedResponder(Psk);

            // --- IKE_SA_INIT ---
            IkeMessage initRequest = client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500);
            byte[] initRequestWire = initRequest.Encode();
            byte[] initResponseWire = responder.HandleInit(initRequestWire);
            client.ProcessInitResponse(IkeMessage.Decode(initResponseWire));

            // --- IKE_AUTH ---
            byte[] authRequestWire = client.BuildAuthRequest();
            byte[] authResponseWire = responder.HandleAuth(authRequestWire);
            bool authenticated = client.ProcessAuthResponse(authResponseWire);

            Assert.True(authenticated);
            Assert.NotNull(client.ChildKeys);
            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);

            // --- ESP data plane both directions ---
            EspSession clientEsp = BuildInitiatorEsp(client);
            EspSession responderEsp = responder.BuildEsp();

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("ping from client"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("ping from client", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("pong from server"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("pong from server", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void FullHandshake_WhenGatewaySelectsGcm_NegotiatesGcmAndEspExchangeSucceeds()
        {
            var idInitiator = new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
            var client = new IkeClient(Psk, idInitiator);
            var responder = new SimulatedResponder(Psk, EspSuiteSelection.AesGcm16());

            byte[] initResponseWire = responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode());
            client.ProcessInitResponse(IkeMessage.Decode(initResponseWire));
            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest())));

            // The client must build the AES-GCM CHILD_SA the gateway selected from our two proposals.
            Assert.NotNull(client.NegotiatedEsp);
            Assert.Equal(EspEncryptionAlgorithm.AesGcm16, client.NegotiatedEsp!.Algorithm);
            Assert.Equal(4, client.ChildKeys!.IntegrityInitiator.Length); // the GCM salt occupies the integrity slice

            EspSession clientEsp = BuildInitiatorEsp(client);
            EspSession responderEsp = responder.BuildEsp();

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("ping via gcm"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("ping via gcm", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("pong via gcm"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("pong via gcm", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void FullHandshake_WithConfigRequest_AssignsVirtualIpAndDns()
        {
            var idInitiator = new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
            // tunnel mode (no USE_TRANSPORT_MODE) + a CFG_REQUEST for a virtual IP, as the IKEv2-native driver will do.
            var client = new IkeClient(Psk, idInitiator, requestTransportMode: false, requestConfiguration: true);
            var responder = new SimulatedResponder(Psk, assignAddress: IPAddress.Parse("10.11.12.13"), assignDns: IPAddress.Parse("8.8.4.4"));

            byte[] initResponseWire = responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode());
            client.ProcessInitResponse(IkeMessage.Decode(initResponseWire));
            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest())));

            Assert.NotNull(client.Configuration);
            Assert.Equal(IPAddress.Parse("10.11.12.13"), client.Configuration!.AssignedIp4Address);
            Assert.Equal(new[] { IPAddress.Parse("8.8.4.4") }, client.Configuration.DnsServers);
        }

        [Fact]
        public void AfterHandshake_DpdAndDelete_RideTheInformationalSkChannel()
        {
            IkeClient client = HandshakeReady(out SimulatedResponder responder);

            // --- DPD (liveness): empty INFORMATIONAL request, message ID continues at 2 ---
            byte[] dpdWire = client.BuildDeadPeerDetection();
            IkeMessage dpd = responder.Decrypt(dpdWire)!;
            Assert.Equal(IkeExchangeType.Informational, dpd.ExchangeType);
            Assert.Empty(dpd.Payloads);
            Assert.Equal(2u, dpd.MessageId);

            // Responder answers with an empty INFORMATIONAL response; the client decrypts it.
            var ack = new IkeMessage
            {
                InitiatorSpi = responder.InitiatorSpi,
                ResponderSpi = responder.ResponderSpi,
                ExchangeType = IkeExchangeType.Informational,
                Flags = IkeHeaderFlags.Response,
                MessageId = dpd.MessageId,
            };
            IkeMessage? gotAck = client.Decrypt(responder.EncryptResponse(ack));
            Assert.NotNull(gotAck);
            Assert.Empty(gotAck!.Payloads);

            // --- DELETE CHILD_SA: next message ID, carries the ESP SPI we chose inbound ---
            IkeMessage delChild = responder.Decrypt(client.BuildDeleteChildSa())!;
            DeletePayload childDelete = delChild.Find<DeletePayload>()!;
            Assert.Equal(IkeProtocolId.Esp, childDelete.ProtocolId);
            Assert.Equal(client.ChildInboundSpi, Assert.Single(childDelete.Spis));
            Assert.Equal(3u, delChild.MessageId);

            // --- DELETE IKE_SA: clean teardown, no SPIs ---
            IkeMessage delIke = responder.Decrypt(client.BuildDeleteIkeSa())!;
            DeletePayload ikeDelete = delIke.Find<DeletePayload>()!;
            Assert.Equal(IkeProtocolId.Ike, ikeDelete.ProtocolId);
            Assert.Empty(ikeDelete.Spis);
            Assert.Equal(4u, delIke.MessageId);
        }

        [Fact]
        public void CreateChildSa_RekeysTheEspSa_AndFreshKeysCarryTrafficBothWays()
        {
            IkeClient client = HandshakeReady(out SimulatedResponder responder);
            byte[] originalInbound = client.ChildInboundSpi;

            ChildSaParameters? rekeyed = client.ProcessRekeyChildSaResponse(
                responder.HandleRekeyChildSa(client.BuildRekeyChildSaRequest()));

            Assert.NotNull(rekeyed);
            Assert.NotEqual(originalInbound, client.ChildInboundSpi); // adopted a fresh inbound SPI
            Assert.Equal(3u, client.NextMessageId);                  // CREATE_CHILD_SA consumed message ID 2

            // The replacement keys must protect traffic in both directions.
            EspSession clientEsp = BuildInitiatorEsp(client);
            EspSession responderEsp = responder.BuildRekeyedEsp();

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("after rekey"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("after rekey", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("rekey pong"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("rekey pong", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void AfterChildSaRekey_DeleteTargetsTheOldInboundSpi_NotTheReplacement()
        {
            IkeClient client = HandshakeReady(out SimulatedResponder responder);
            byte[] oldInboundSpi = client.ChildInboundSpi; // the SA being replaced — captured before the rekey overwrites it

            Assert.NotNull(client.ProcessRekeyChildSaResponse(responder.HandleRekeyChildSa(client.BuildRekeyChildSaRequest())));
            byte[] newInboundSpi = client.ChildInboundSpi;
            Assert.NotEqual(oldInboundSpi, newInboundSpi);

            // RFC 7296 §2.8: the initiator retires the old CHILD_SA by its (old) inbound SPI on the live IKE SA.
            IkeMessage delChild = responder.Decrypt(client.BuildDeleteChildSa(oldInboundSpi))!;
            DeletePayload childDelete = delChild.Find<DeletePayload>()!;
            Assert.Equal(IkeProtocolId.Esp, childDelete.ProtocolId);
            Assert.Equal(oldInboundSpi, Assert.Single(childDelete.Spis)); // the OLD SPI, not the replacement
            Assert.Equal(3u, delChild.MessageId);                         // CREATE_CHILD_SA was message ID 2
        }

        [Fact]
        public void AfterIkeSaRekey_DeleteRidesTheOldSa_AndNamesTheOldIkeSpis()
        {
            IkeClient client = HandshakeReady(out SimulatedResponder responder);
            byte[] oldInitiatorSpi = responder.InitiatorSpi; // the retired IKE SA's header SPIs
            byte[] oldResponderSpi = responder.ResponderSpi;

            Assert.True(client.ProcessRekeyIkeSaResponse(responder.HandleRekeyIkeSa(client.BuildRekeyIkeSaRequest())));

            // RFC 7296 §2.18: the DELETE of the replaced IKE SA must be encrypted with the OLD keys and addressed with
            // the OLD SPIs — it was prepared the instant before the swing, so the new keys cannot read it.
            byte[]? deleteOld = client.TakePendingOldIkeSaDelete();
            Assert.NotNull(deleteOld);
            Assert.Null(client.TakePendingOldIkeSaDelete()); // draining is one-shot

            IkeMessage delIke = responder.Decrypt(deleteOld!)!; // the OLD cipher reads it
            DeletePayload ikeDelete = delIke.Find<DeletePayload>()!;
            Assert.Equal(IkeProtocolId.Ike, ikeDelete.ProtocolId);
            Assert.Empty(ikeDelete.Spis);                       // an IKE-SA DELETE carries no SPIs (RFC 7296 §3.11)
            Assert.Equal(oldInitiatorSpi, delIke.InitiatorSpi);
            Assert.Equal(oldResponderSpi, delIke.ResponderSpi);
            Assert.Equal(3u, delIke.MessageId);                 // rekey consumed ID 2 on the old SA, so the DELETE is 3

            // The replacement SA cannot decrypt a DELETE meant for the retired SA.
            Assert.Null(responder.DecryptRekeyed(deleteOld!));
        }

        [Fact]
        public void CreateChildSa_RekeysTheIkeSa_AndTheNewKeysCarryTheSkChannel()
        {
            IkeClient client = HandshakeReady(out SimulatedResponder responder);
            byte[] originalInitiatorSpi = responder.InitiatorSpi; // the old IKE SA's initiator SPI

            // CREATE_CHILD_SA rekeying the IKE SA: built on the OLD SA (message ID 2), then swing onto the new SA.
            byte[] rekeyRequest = client.BuildRekeyIkeSaRequest();
            Assert.True(client.ProcessRekeyIkeSaResponse(responder.HandleRekeyIkeSa(rekeyRequest)));

            Assert.Equal(0u, client.NextMessageId);                       // the replacement IKE SA counts from 0
            Assert.Equal(8, responder.NewInitiatorSpi.Length);
            Assert.NotEqual(originalInitiatorSpi, responder.NewInitiatorSpi); // a fresh 8-byte initiator SPI

            // A DPD now rides the NEW SK channel: new SPIs in the header, message ID 0, readable only by the new keys.
            byte[] dpdWire = client.BuildDeadPeerDetection();
            IkeMessage dpd = responder.DecryptRekeyed(dpdWire)!;
            Assert.Equal(IkeExchangeType.Informational, dpd.ExchangeType);
            Assert.Empty(dpd.Payloads);
            Assert.Equal(0u, dpd.MessageId);
            Assert.Equal(responder.NewInitiatorSpi, dpd.InitiatorSpi);
            Assert.Equal(responder.NewResponderSpi, dpd.ResponderSpi);

            // The old SK keys are retired — the old cipher must not decrypt traffic on the rekeyed SA.
            Assert.Null(responder.Decrypt(dpdWire));
        }

        [Fact]
        public void FullHandshake_WithEapMsChapV2_AuthenticatesAndChildSaCarriesTraffic()
        {
            var idInitiator = new IdentificationPayload
            {
                IsInitiator = true,
                IdType = IkeIdType.Rfc822Address,
                Data = System.Text.Encoding.ASCII.GetBytes("user@example.com"),
            };
            var client = new IkeClient(Psk, idInitiator, eapUserName: "User", eapPassword: "clientPass");
            var responder = new SimulatedResponder(Psk, eapUserName: "User", eapPassword: "clientPass");

            // --- IKE_SA_INIT ---
            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            // --- IKE_AUTH + EAP-MSCHAPv2 loop (Identity → Challenge/Response → Success → MSK AUTH) ---
            byte[]? requestWire = client.BuildAuthRequestEap();
            while (requestWire is not null)
                requestWire = client.ProcessAuthResponseEap(responder.HandleAuthEap(requestWire));

            Assert.True(client.EapEstablished);
            Assert.False(client.EapFailed);
            Assert.NotNull(client.ChildKeys);
            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);
            Assert.Equal(6u, client.NextMessageId); // IKE_AUTH consumed IDs 1–5: msg3 + EAP Identity/Challenge/Success + final MSK AUTH

            // --- ESP data plane both directions, keyed from the EAP-authenticated CHILD_SA ---
            EspSession clientEsp = BuildInitiatorEsp(client);
            EspSession responderEsp = responder.BuildEsp();

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("eap ping"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("eap ping", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("eap pong"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("eap pong", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void EapMsChapV2_WithWrongPassword_FailsWithoutEstablishing()
        {
            var idInitiator = new IdentificationPayload
            {
                IsInitiator = true,
                IdType = IkeIdType.Rfc822Address,
                Data = System.Text.Encoding.ASCII.GetBytes("user@example.com"),
            };
            // The gateway PSK is correct (its AUTH verifies), but the EAP password is wrong → MS-CHAPv2 NT-Response mismatch.
            var client = new IkeClient(Psk, idInitiator, eapUserName: "User", eapPassword: "wrongPass");
            var responder = new SimulatedResponder(Psk, eapUserName: "User", eapPassword: "clientPass");

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            byte[]? requestWire = client.BuildAuthRequestEap();
            while (requestWire is not null)
                requestWire = client.ProcessAuthResponseEap(responder.HandleAuthEap(requestWire));

            Assert.True(client.EapFailed);
            Assert.False(client.EapEstablished);
            Assert.Null(client.ChildKeys);
        }

        // Runs IKE_SA_INIT + IKE_AUTH and returns a client with a live SK channel plus its responder.
        static IkeClient HandshakeReady(out SimulatedResponder responder)
        {
            var idInitiator = new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
            var client = new IkeClient(Psk, idInitiator);
            responder = new SimulatedResponder(Psk);
            client.ProcessInitResponse(IkeMessage.Decode(responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));
            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest())));
            return client;
        }

        static EspSession BuildInitiatorEsp(IkeClient client)
        {
            ChildSaKeys k = client.ChildKeys!;
            EspSuiteSelection esp = client.NegotiatedEsp!;
            EspCipherSuite send = esp.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
            EspCipherSuite receive = esp.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
            return new EspSession(ToSpi(client.ChildOutboundSpi), send, ToSpi(client.ChildInboundSpi), receive);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        /// <summary>A minimal in-process IKEv2 responder used only to validate the client against RFC behaviour.</summary>
        sealed class SimulatedResponder
        {
            readonly HmacPrf _prf = HmacPrf.Sha256();
            readonly ModpDhGroup _dh = ModpDhGroup.Group14();
            readonly byte[] _psk;
            readonly EspSuiteSelection _esp; // the ESP CHILD_SA suite this responder selects in IKE_AUTH
            readonly IPAddress? _assignAddress; // virtual IP to hand back in a CFG_REPLY, when the client asks
            readonly IPAddress? _assignDns;
            readonly string? _eapUserName; // EAP-MSCHAPv2 credentials this responder validates against
            readonly string? _eapPassword;
            readonly byte[] _privateKey;
            readonly byte[] _publicKey;
            readonly byte[] _spi = new byte[8];
            readonly byte[] _nonce;

            byte[] _initRequestWire = Array.Empty<byte>();
            byte[] _initResponseWire = Array.Empty<byte>();
            byte[] _initiatorNonce = Array.Empty<byte>();
            byte[] _initiatorSpi = new byte[8];
            IkeKeyMaterial? _keys;
            IkeCipher? _cipher;

            public SimulatedResponder(byte[] psk, EspSuiteSelection? esp = null, IPAddress? assignAddress = null,
                IPAddress? assignDns = null, string? eapUserName = null, string? eapPassword = null)
            {
                _psk = psk;
                _esp = esp ?? EspSuiteSelection.AesCbcHmacSha256();
                _assignAddress = assignAddress;
                _assignDns = assignDns;
                _eapUserName = eapUserName;
                _eapPassword = eapPassword;
                _privateKey = _dh.GeneratePrivateKey();
                _publicKey = _dh.DerivePublicValue(_privateKey);
                for (int i = 0; i < 8; i++) _spi[i] = (byte)(0x90 + i);
                _nonce = new byte[32];
                for (int i = 0; i < 32; i++) _nonce[i] = (byte)(0xC0 + i);
                ChildInboundSpi = new byte[] { 0x77, 0x66, 0x55, 0x44 };
            }

            public byte[] ChildInboundSpi { get; }
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

            // Exposed so post-auth INFORMATIONAL/CREATE_CHILD_SA tests can drive the SK channel both ways.
            public byte[] InitiatorSpi => _initiatorSpi;
            public byte[] ResponderSpi => _spi;
            public IkeMessage? Decrypt(byte[] wire) => _cipher!.DecryptMessage(wire);
            public byte[] EncryptResponse(IkeMessage message) => _cipher!.EncryptMessage(message);

            public byte[] HandleInit(byte[] requestWire)
            {
                _initRequestWire = requestWire;
                IkeMessage request = IkeMessage.Decode(requestWire);
                _initiatorSpi = request.InitiatorSpi;
                _initiatorNonce = request.Find<NoncePayload>()!.Nonce;
                byte[] initiatorPublic = request.Find<KeyExchangePayload>()!.KeyData;

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.IkeSaInit,
                    Flags = IkeHeaderFlags.Response,
                };
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(IkeProposals.DefaultIke());
                response.Payloads.Add(sa);
                response.Payloads.Add(new KeyExchangePayload
                {
                    DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048,
                    KeyData = _publicKey,
                });
                response.Payloads.Add(new NoncePayload { Nonce = _nonce });

                _initResponseWire = response.Encode();
                byte[] shared = _dh.DeriveSharedSecret(_privateKey, initiatorPublic);
                _keys = IkeKeyMaterial.DeriveDefault(_initiatorNonce, _nonce, shared, _initiatorSpi, _spi);
                _cipher = IkeCipher.ForResponder(_keys);
                return _initResponseWire;
            }

            public byte[] HandleAuth(byte[] requestWire)
            {
                IkeMessage request = _cipher!.DecryptMessage(requestWire)!;
                IdentificationPayload idI = request.Payloads.OfType<IdentificationPayload>().Single(p => p.IsInitiator);
                AuthenticationPayload auth = request.Find<AuthenticationPayload>()!;

                byte[] expected = IkePskAuth.ComputeInitiatorAuth(
                    _prf, _psk, _initRequestWire, _nonce, _keys!.SkPi, idI.BodyBytes());
                Assert.Equal(expected, auth.Data); // the client authenticated correctly

                // The client now offers two ESP proposals (AES-CBC then AES-GCM); both carry the same SPI.
                ChildOutboundSpi = request.Find<SecurityAssociationPayload>()!.Proposals.First().Spi;

                var idR = new IdentificationPayload { IsInitiator = false, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 10, 0, 0, 1 } };
                byte[] responderAuth = IkePskAuth.ComputeResponderAuth(
                    _prf, _psk, _initResponseWire, _initiatorNonce, _keys.SkPr, idR.BodyBytes());

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.IkeAuth,
                    Flags = IkeHeaderFlags.Response,
                    MessageId = 1,
                };
                response.Payloads.Add(idR);
                response.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = responderAuth });

                // Echo a CFG_REPLY when the client sent a CFG_REQUEST and we were told what to assign.
                if (_assignAddress is not null && request.Find<ConfigurationPayload>()?.ConfigType == IkeConfigType.Request)
                {
                    var cp = new ConfigurationPayload { ConfigType = IkeConfigType.Reply };
                    cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Address, _assignAddress.GetAddressBytes()));
                    if (_assignDns is not null)
                        cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Dns, _assignDns.GetAddressBytes()));
                    response.Payloads.Add(cp);
                }

                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(_esp.Algorithm == EspEncryptionAlgorithm.AesGcm16
                    ? IkeProposals.GcmEsp(ChildInboundSpi)
                    : IkeProposals.DefaultEsp(ChildInboundSpi));
                response.Payloads.Add(sa);
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                response.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));
                return _cipher.EncryptMessage(response);
            }

            public EspSession BuildEsp()
            {
                ChildSaKeys k = ChildSaKeys.Derive(_prf, _keys!.SkD, _initiatorNonce, _nonce,
                    _esp.EncryptionKeyLengthBytes, _esp.SecondSliceLengthBytes);
                // Responder sends with the responder→initiator keys, receives with initiator→responder keys.
                EspCipherSuite send = _esp.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
                EspCipherSuite receive = _esp.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
                return new EspSession(ToSpi(ChildOutboundSpi), send, ToSpi(ChildInboundSpi), receive);
            }

            // ---- CREATE_CHILD_SA rekey state + handlers ----
            byte[] _rekeyInitiatorNonce = Array.Empty<byte>(); // client's Ni from the rekey request
            byte[] _rekeyNonce = Array.Empty<byte>();          // our Nr
            byte[] _rekeyInbound = Array.Empty<byte>();         // the new SPI we receive on
            byte[] _rekeyOutbound = Array.Empty<byte>();        // the client's new inbound SPI = our outbound

            public byte[] HandleRekeyChildSa(byte[] wire)
            {
                IkeMessage request = _cipher!.DecryptMessage(wire)!;
                _rekeyInitiatorNonce = request.Find<NoncePayload>()!.Nonce;
                _rekeyOutbound = request.Find<SecurityAssociationPayload>()!.Proposals.First().Spi;
                _rekeyInbound = new byte[] { 0x12, 0x34, 0x56, 0x78 };
                _rekeyNonce = new byte[32];
                for (int i = 0; i < 32; i++) _rekeyNonce[i] = (byte)(0xA0 + i);

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.CreateChildSa,
                    Flags = IkeHeaderFlags.Response,
                    MessageId = request.MessageId,
                };
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(_esp.Algorithm == EspEncryptionAlgorithm.AesGcm16
                    ? IkeProposals.GcmEsp(_rekeyInbound)
                    : IkeProposals.DefaultEsp(_rekeyInbound));
                response.Payloads.Add(sa);
                response.Payloads.Add(new NoncePayload { Nonce = _rekeyNonce });
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                return _cipher.EncryptMessage(response);
            }

            public EspSession BuildRekeyedEsp()
            {
                ChildSaKeys k = ChildSaKeys.Derive(_prf, _keys!.SkD, _rekeyInitiatorNonce, _rekeyNonce,
                    _esp.EncryptionKeyLengthBytes, _esp.SecondSliceLengthBytes);
                EspCipherSuite send = _esp.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
                EspCipherSuite receive = _esp.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
                return new EspSession(ToSpi(_rekeyOutbound), send, ToSpi(_rekeyInbound), receive);
            }

            // ---- CREATE_CHILD_SA rekey of the IKE SA itself (new SPIs + fresh D-H) ----
            byte[] _ikeRekeyInitiatorSpi = Array.Empty<byte>(); // the client's new IKE SPI
            byte[] _ikeRekeyResponderSpi = Array.Empty<byte>(); // ours
            IkeCipher? _rekeyedCipher;                          // the SK cipher of the replacement IKE SA

            public byte[] NewInitiatorSpi => _ikeRekeyInitiatorSpi;
            public byte[] NewResponderSpi => _ikeRekeyResponderSpi;

            /// <summary>Decrypts a message that rode the rekeyed (new) IKE SA — only the new keys can read it.</summary>
            public IkeMessage? DecryptRekeyed(byte[] wire) => _rekeyedCipher!.DecryptMessage(wire);

            public byte[] HandleRekeyIkeSa(byte[] wire)
            {
                // The rekey exchange itself is protected by the OLD SA, so decrypt/encrypt with the current cipher.
                IkeMessage request = _cipher!.DecryptMessage(wire)!;
                byte[] initiatorNonce = request.Find<NoncePayload>()!.Nonce;
                byte[] initiatorPublic = request.Find<KeyExchangePayload>()!.KeyData;
                _ikeRekeyInitiatorSpi = request.Find<SecurityAssociationPayload>()!.Proposals.First().Spi;

                _ikeRekeyResponderSpi = new byte[8];
                for (int i = 0; i < 8; i++) _ikeRekeyResponderSpi[i] = (byte)(0xB0 + i);
                byte[] responderNonce = new byte[32];
                for (int i = 0; i < 32; i++) responderNonce[i] = (byte)(0xD0 + i);
                byte[] privateKey = _dh.GeneratePrivateKey();
                byte[] publicKey = _dh.DerivePublicValue(privateKey);
                byte[] shared = _dh.DeriveSharedSecret(privateKey, initiatorPublic);

                // New SKEYSEED chains to the old SA via SK_d, exactly as the client derives it (RFC 7296 §2.18).
                IkeKeyMaterial newKeys = IkeKeyMaterial.DeriveRekeyDefault(
                    _keys!.SkD, initiatorNonce, responderNonce, shared, _ikeRekeyInitiatorSpi, _ikeRekeyResponderSpi);
                _rekeyedCipher = IkeCipher.ForResponder(newKeys);

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi, // the rekey exchange's header SPIs still belong to the old SA
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.CreateChildSa,
                    Flags = IkeHeaderFlags.Response,
                    MessageId = request.MessageId,
                };
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(IkeProposals.RekeyIke(_ikeRekeyResponderSpi));
                response.Payloads.Add(sa);
                response.Payloads.Add(new KeyExchangePayload
                {
                    DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048,
                    KeyData = publicKey,
                });
                response.Payloads.Add(new NoncePayload { Nonce = responderNonce });
                return _cipher.EncryptMessage(response);
            }

            // ---- IKE_AUTH with EAP-MSCHAPv2 (server-side), RFC 7296 §2.16 + draft-kamath-pppext-eap-mschapv2 ----
            int _eapStep;
            byte[] _eapAuthChallenge = Array.Empty<byte>();
            byte[] _eapPeerChallenge = Array.Empty<byte>();
            byte[] _eapMsk = Array.Empty<byte>();
            byte[] _eapInitiatorIdBody = Array.Empty<byte>();
            IdentificationPayload? _eapIdR;

            /// <summary>Drives one IKE_AUTH round of the EAP exchange and returns the response wire.</summary>
            public byte[] HandleAuthEap(byte[] requestWire)
            {
                IkeMessage request = _cipher!.DecryptMessage(requestWire)!;
                EapPayload? eap = request.Find<EapPayload>();
                AuthenticationPayload? auth = request.Find<AuthenticationPayload>();

                // Message 3: IDi + SAi2 + TS, NO AUTH. Respond IDr + responder PSK AUTH + EAP-Request/Identity.
                if (_eapStep == 0)
                {
                    IdentificationPayload idI = request.Payloads.OfType<IdentificationPayload>().Single(p => p.IsInitiator);
                    _eapInitiatorIdBody = idI.BodyBytes();
                    ChildOutboundSpi = request.Find<SecurityAssociationPayload>()!.Proposals.First().Spi;

                    _eapIdR = new IdentificationPayload { IsInitiator = false, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 10, 0, 0, 1 } };
                    byte[] responderAuth = IkePskAuth.ComputeResponderAuth(
                        _prf, _psk, _initResponseWire, _initiatorNonce, _keys!.SkPr, _eapIdR.BodyBytes());

                    IkeMessage resp = NewAuthResponse(request.MessageId);
                    resp.Payloads.Add(_eapIdR);
                    resp.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = responderAuth });
                    resp.Payloads.Add(new EapPayload { Message = EapPacket.Build(EapCode.Request, 1, 1, Array.Empty<byte>()) }); // Identity
                    _eapStep = 1;
                    return _cipher.EncryptMessage(resp);
                }

                if (eap is not null) return HandleEapResponse(request, eap.Message);

                // Final message (7): the initiator's AUTH computed from the MSK. Verify it and answer with our MSK AUTH + SAr2.
                byte[] expected = IkePskAuth.ComputeInitiatorAuth(
                    _prf, _eapMsk, _initRequestWire, _nonce, _keys!.SkPi, _eapInitiatorIdBody);
                Assert.Equal(expected, auth!.Data);

                byte[] responderMskAuth = IkePskAuth.ComputeResponderAuth(
                    _prf, _eapMsk, _initResponseWire, _initiatorNonce, _keys.SkPr, _eapIdR!.BodyBytes());
                IkeMessage final = NewAuthResponse(request.MessageId);
                final.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = responderMskAuth });
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(_esp.Algorithm == EspEncryptionAlgorithm.AesGcm16
                    ? IkeProposals.GcmEsp(ChildInboundSpi)
                    : IkeProposals.DefaultEsp(ChildInboundSpi));
                final.Payloads.Add(sa);
                final.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                final.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                final.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));
                return _cipher.EncryptMessage(final);
            }

            byte[] HandleEapResponse(IkeMessage request, byte[] msg)
            {
                byte type = msg.Length >= 5 ? msg[4] : (byte)0;

                if (type == 1) // EAP-Response/Identity → MS-CHAPv2 Challenge
                {
                    _eapAuthChallenge = new byte[16];
                    for (int i = 0; i < 16; i++) _eapAuthChallenge[i] = (byte)(0x10 + i);
                    _eapStep = 2;
                    return WrapEap(request.MessageId, EapCode.Request, 26, BuildChallengeData(_eapAuthChallenge));
                }

                if (type == 26)
                {
                    byte opCode = msg[5];
                    if (opCode == 2) // Response (NT-Response) → verify, then Success
                    {
                        int valueSize = msg[9];
                        _eapPeerChallenge = new byte[16];
                        Buffer.BlockCopy(msg, 10, _eapPeerChallenge, 0, 16);
                        byte[] ntResponse = new byte[24];
                        Buffer.BlockCopy(msg, 10 + 24, ntResponse, 0, 24);

                        byte[] expectedNt = MsChapV2.GenerateNTResponse(_eapAuthChallenge, _eapPeerChallenge, _eapUserName!, _eapPassword!);
                        if (!expectedNt.AsSpan().SequenceEqual(ntResponse)) // wrong password → EAP-Failure
                            return WrapEap(request.MessageId, EapCode.Failure, null, Array.Empty<byte>());

                        _eapMsk = MsChapV2.DeriveMsk(_eapPassword!, ntResponse);
                        byte[] digest = MsChapV2.GenerateAuthenticatorResponse(
                            _eapAuthChallenge, _eapPeerChallenge, ntResponse, _eapUserName!, _eapPassword!);
                        byte[] message = System.Text.Encoding.ASCII.GetBytes("S=" + ToHex(digest));
                        _eapStep = 3;
                        return WrapEap(request.MessageId, EapCode.Request, 26, BuildSuccessData(msg[6], message));
                    }
                    if (opCode == 3) // Success Response → EAP-Success
                    {
                        _eapStep = 4;
                        return WrapEap(request.MessageId, EapCode.Success, null, Array.Empty<byte>());
                    }
                }
                throw new InvalidOperationException("unexpected EAP response");
            }

            IkeMessage NewAuthResponse(uint messageId) => new IkeMessage
            {
                InitiatorSpi = _initiatorSpi,
                ResponderSpi = _spi,
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Response,
                MessageId = messageId,
            };

            byte[] WrapEap(uint messageId, EapCode code, byte? type, byte[] typeData)
            {
                IkeMessage resp = NewAuthResponse(messageId);
                byte id = code == EapCode.Success ? (byte)3 : (byte)(_eapStep + 1);
                resp.Payloads.Add(new EapPayload { Message = EapPacket.Build(code, id, type, typeData) });
                return _cipher!.EncryptMessage(resp);
            }

            // MS-CHAPv2 Challenge type-data: OpCode=1 | ID | MS-Length(2) | Value-Size=16 | Challenge(16) | Name.
            static byte[] BuildChallengeData(byte[] challenge)
            {
                byte[] name = System.Text.Encoding.ASCII.GetBytes("server");
                int msLen = 4 + 1 + 16 + name.Length;
                byte[] d = new byte[msLen];
                d[0] = 1; d[1] = 0x10;
                d[2] = (byte)(msLen >> 8); d[3] = (byte)msLen;
                d[4] = 16;
                Buffer.BlockCopy(challenge, 0, d, 5, 16);
                Buffer.BlockCopy(name, 0, d, 21, name.Length);
                return d;
            }

            // MS-CHAPv2 Success type-data: OpCode=3 | ID | MS-Length(2) | Message("S=<hex>").
            static byte[] BuildSuccessData(byte msChapId, byte[] message)
            {
                int msLen = 4 + message.Length;
                byte[] d = new byte[msLen];
                d[0] = 3; d[1] = msChapId;
                d[2] = (byte)(msLen >> 8); d[3] = (byte)msLen;
                Buffer.BlockCopy(message, 0, d, 4, message.Length);
                return d;
            }

            static string ToHex(byte[] bytes)
            {
                var sb = new System.Text.StringBuilder(bytes.Length * 2);
                foreach (byte b in bytes) sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }
    }
}
