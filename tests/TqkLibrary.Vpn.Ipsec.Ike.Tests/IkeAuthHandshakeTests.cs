using System.Net;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.Ipsec.Ike;
using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Models;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
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

        static EspSession BuildInitiatorEsp(IkeClient client)
        {
            ChildSaKeys k = client.ChildKeys!;
            EspCipherSuite send = EspCipherSuite.AesCbcHmacSha256(k.EncryptionInitiator, k.IntegrityInitiator);
            EspCipherSuite receive = EspCipherSuite.AesCbcHmacSha256(k.EncryptionResponder, k.IntegrityResponder);
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

            public SimulatedResponder(byte[] psk)
            {
                _psk = psk;
                _privateKey = _dh.GeneratePrivateKey();
                _publicKey = _dh.DerivePublicValue(_privateKey);
                for (int i = 0; i < 8; i++) _spi[i] = (byte)(0x90 + i);
                _nonce = new byte[32];
                for (int i = 0; i < 32; i++) _nonce[i] = (byte)(0xC0 + i);
                ChildInboundSpi = new byte[] { 0x77, 0x66, 0x55, 0x44 };
            }

            public byte[] ChildInboundSpi { get; }
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

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

                ChildOutboundSpi = request.Find<SecurityAssociationPayload>()!.Proposals.Single().Spi;

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
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(IkeProposals.DefaultEsp(ChildInboundSpi));
                response.Payloads.Add(sa);
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                response.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));
                return _cipher.EncryptMessage(response);
            }

            public EspSession BuildEsp()
            {
                ChildSaKeys k = ChildSaKeys.DeriveDefault(_keys!.SkD, _initiatorNonce, _nonce);
                // Responder sends with the responder→initiator keys, receives with initiator→responder keys.
                EspCipherSuite send = EspCipherSuite.AesCbcHmacSha256(k.EncryptionResponder, k.IntegrityResponder);
                EspCipherSuite receive = EspCipherSuite.AesCbcHmacSha256(k.EncryptionInitiator, k.IntegrityInitiator);
                return new EspSession(ToSpi(ChildOutboundSpi), send, ToSpi(ChildInboundSpi), receive);
            }
        }
    }
}
