using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    /// <summary>
    /// Drives the real <see cref="IkeV1Client"/> through a full IKEv1 exchange in-process: Main Mode MM1→MM6 (PSK)
    /// then Quick Mode QM1→QM3 against a hand-written <see cref="SimulatedResponderV1"/>, then both sides build
    /// <see cref="EspSession"/>s from the Phase-2 keys and exchange a protected packet each direction. This pins the
    /// IKEv1 encrypted-exchange math (Main Mode HASH_I/HASH_R auth, the CBC IV chain, the Quick-Mode derived IV,
    /// the client's HASH(1) and its HASH(3) verified by the responder, SKEYID_d → ESP keymat) offline — previously
    /// only live-tested against VPN Gate. The DPD and Delete round-trips at the end pin the derived-IV Informational
    /// cipher. Note: the client does NOT authenticate the responder's QM2 HASH(2) (a production interop choice — see
    /// <see cref="IkeV1Client.ProcessQuickMode2"/>), so the responder computes HASH(2) for fidelity but it is not pinned here.
    ///
    /// The responder hand-rolls the tiny ISAKMP framing (28-byte header + TLV payload chain) so no production-code
    /// change (e.g. InternalsVisibleTo) is needed: <c>IsakmpMessage.EncodePayloadChain/WriteHeader/...</c> are internal.
    /// </summary>
    public class IkeV1HandshakeTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");

        [Fact]
        public void FullMainModeAndQuickMode_ThenEspExchange_Succeeds()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);

            // --- Main Mode ---
            byte[] mm1 = client.BuildMainMode1();
            byte[] mm2 = responder.HandleMainMode1(mm1);
            client.ProcessMainMode2(mm2);

            byte[] mm3 = client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback);
            byte[] mm4 = responder.HandleMainMode3(mm4Input: mm3, cookieR: responder.ResponderCookie);
            client.ProcessMainMode4(mm4);

            byte[] mm5 = client.BuildMainMode5();
            byte[] mm6 = responder.HandleMainMode5(mm5); // verifies HASH_I internally
            Assert.True(client.ProcessMainMode6(mm6));    // verifies HASH_R

            // --- Quick Mode ---
            byte[] qm1 = client.BuildQuickMode1();
            byte[] qm2 = responder.HandleQuickMode1(qm1); // captures client SPI + Ni; builds SA + Nr (+ HASH(2), which the client does not verify)
            Assert.True(client.ProcessQuickMode2(qm2));    // accepts the responder's ESP SPI; HASH(2) is not authenticated

            byte[] qm3 = client.BuildQuickMode3();
            responder.HandleQuickMode3(qm3); // verifies HASH(3) internally

            // SPI orientation (mirror Phase2Keys_TwoParties): the SA on the responder's SPI is the client's
            // outbound and the responder's inbound — same keys on both sides.
            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);

            // --- Phase-2 keys + ESP data plane both directions ---
            IkeV1Phase2Keys clientKeys = client.CreatePhase2Keys();
            IkeV1Phase2Keys responderKeys = responder.CreatePhase2Keys();

            // Sanity: the key set agrees on the shared SAs.
            Assert.Equal(clientKeys.OutboundEncryption, responderKeys.InboundEncryption);
            Assert.Equal(clientKeys.InboundEncryption, responderKeys.OutboundEncryption);

            EspSession clientEsp = new(
                ToSpi(client.ChildOutboundSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.OutboundEncryption, clientKeys.OutboundIntegrity),
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.InboundEncryption, clientKeys.InboundIntegrity));
            EspSession responderEsp = new(
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(responderKeys.OutboundEncryption, responderKeys.OutboundIntegrity),
                ToSpi(responder.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(responderKeys.InboundEncryption, responderKeys.InboundIntegrity));

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("ping from client"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("ping from client", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("pong from server"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("pong from server", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void Dpd_AndDelete_RoundTripThroughDerivedIvInformationalCipher()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);
            DriveToQuickModeComplete(client, responder);

            // DPD: client probes; responder decrypts the Informational and reads the R-U-THERE notify.
            byte[] probe = client.BuildDpdRUThere(0x11223344);
            (ushort notifyType, uint sequence) = responder.ReadDpdNotify(probe);
            Assert.Equal(IkeV1Dpd.RUThere, notifyType);
            Assert.Equal(0x11223344u, sequence);

            // The responder answers with a DPD ACK that the client must classify as DpdAck.
            byte[] ack = responder.BuildDpdAck(sequence);
            IkeV1InformationalResult result = client.ProcessInformational(ack);
            Assert.Equal(IkeV1InformationalKind.DpdAck, result.Kind);
            Assert.Equal(sequence, result.Sequence);

            // Delete: client tears the ESP CHILD SA down; responder confirms a Delete payload for ESP.
            byte[] delete = client.BuildDeleteEsp();
            Assert.Equal(IkeV1Constants.Protocol.Esp, responder.ReadDeleteProtocol(delete));
        }

        static void DriveToQuickModeComplete(IkeV1Client client, SimulatedResponderV1 responder)
        {
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));
            client.ProcessMainMode4(responder.HandleMainMode3(client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback), responder.ResponderCookie));
            Assert.True(client.ProcessMainMode6(responder.HandleMainMode5(client.BuildMainMode5())));
            Assert.True(client.ProcessQuickMode2(responder.HandleQuickMode1(client.BuildQuickMode1())));
            responder.HandleQuickMode3(client.BuildQuickMode3());
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        /// <summary>
        /// A minimal in-process IKEv1 (Main Mode PSK + Quick Mode) responder used only to validate the real client.
        /// It hand-rolls ISAKMP framing (the codec's chain helpers are <c>internal</c>) and reuses the public crypto
        /// helpers (<see cref="IkeV1KeyMaterial"/>, <see cref="IkeV1Auth"/>, <see cref="IkeV1QuickMode"/>, …).
        /// </summary>
        sealed class SimulatedResponderV1
        {
            const byte IdTypeIpv4 = 1;

            readonly byte[] _psk;
            readonly HashAlgorithmName _hash = HashAlgorithmName.SHA1;
            readonly HmacPrf _prf = new(HashAlgorithmName.SHA1);
            readonly ModpDhGroup _dh = ModpDhGroup.Group14(); // MM2 echoes MODP-2048 → the client uses group 14
            readonly byte[] _cookieI;
            readonly byte[] _cookieR = Bytes(0x90, 8);
            readonly byte[] _privateKey;
            readonly byte[] _keResponder;
            readonly byte[] _nonceResponder = Bytes(0x40, 16);

            byte[] _keInitiator = Array.Empty<byte>();
            byte[] _nonceInitiator = Array.Empty<byte>();
            byte[] _saInitiatorBody = Array.Empty<byte>();
            IkeV1KeyMaterial? _keys;
            IkeV1Cipher? _phase1Cipher;
            byte[] _phase1LastIv = Array.Empty<byte>();

            uint _quickModeId;
            IkeV1Cipher? _quickModeCipher;
            byte[] _quickModeNonceInitiator = Array.Empty<byte>();

            public SimulatedResponderV1(byte[] psk, byte[] initiatorCookie)
            {
                _psk = psk;
                _cookieI = initiatorCookie;
                _privateKey = _dh.GeneratePrivateKey();
                _keResponder = _dh.DerivePublicValue(_privateKey);
                ChildInboundSpi = new byte[] { 0x51, 0x52, 0x53, 0x54 };
            }

            /// <summary>The 8-byte responder cookie picked at construction.</summary>
            public byte[] ResponderCookie => _cookieR;

            /// <summary>The ESP SPI we chose (the client sends to us on it).</summary>
            public byte[] ChildInboundSpi { get; }

            /// <summary>The ESP SPI the client chose (we send to it on it).</summary>
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

            // ---- Main Mode ----

            /// <summary>MM2: echo the FIRST transform of the client's proposal (AES-256/SHA1/MODP-2048) + the RFC 3947 VID.</summary>
            public byte[] HandleMainMode1(byte[] mm1)
            {
                IsakmpMessage request = IsakmpMessage.Decode(mm1);
                // The HASH inputs use the client's exact MM1 SA body; reconstruct it the same way the client did.
                _saInitiatorBody = IkeV1Proposals.Phase1().BodyBytes();

                IsakmpProposal clientProposal = request.Find<IsakmpSaPayload>()!.Proposals[0];
                IsakmpTransform first = clientProposal.Transforms[0]; // AES-256 + SHA1 + MODP-2048

                var chosenProposal = new IsakmpProposal
                {
                    Number = clientProposal.Number,
                    ProtocolId = clientProposal.ProtocolId,
                    Spi = clientProposal.Spi,
                };
                var chosenTransform = new IsakmpTransform(first.Number, first.TransformId);
                foreach (IsakmpAttribute attribute in first.Attributes) chosenTransform.Attributes.Add(attribute);
                chosenProposal.Transforms.Add(chosenTransform);

                var sa = new IsakmpSaPayload();
                sa.Proposals.Add(chosenProposal);

                var payloads = new List<IsakmpPayload>
                {
                    sa,
                    new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947),
                };
                return EncodeClear(IsakmpExchangeType.MainMode, 0, payloads);
            }

            /// <summary>MM4: read KE_i + Ni, then build KE_r + Nr, derive the key set, and arm the Phase-1 cipher.</summary>
            public byte[] HandleMainMode3(byte[] mm4Input, byte[] cookieR)
            {
                _ = cookieR; // the responder cookie is fixed at construction; the parameter only documents intent.
                IsakmpMessage request = IsakmpMessage.Decode(mm4Input);
                _keInitiator = request.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
                _nonceInitiator = request.FindRaw(IsakmpPayloadType.Nonce)!.Body;

                byte[] shared = _dh.DeriveSharedSecret(_privateKey, _keInitiator);
                _keys = IkeV1KeyMaterial.DeriveMainMode(
                    _hash, _psk, _nonceInitiator, _nonceResponder, shared,
                    _cookieI, _cookieR, _keInitiator, _keResponder, cipherKeyLength: 32, blockSize: 16);
                _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);

                // The client's ProcessMainMode4 only reads KeyExchange + Nonce; NAT-D is optional.
                var payloads = new List<IsakmpPayload>
                {
                    new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keResponder),
                    new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder),
                };
                return EncodeClear(IsakmpExchangeType.MainMode, 0, payloads);
            }

            /// <summary>MM5: decrypt, verify HASH_I, then build the encrypted MM6 (IDr + HASH_R).</summary>
            public byte[] HandleMainMode5(byte[] mm5)
            {
                List<IsakmpPayload> payloads = DecryptChain(_phase1Cipher!, mm5);
                byte[] idiBody = Raw(payloads, IsakmpPayloadType.Identification);
                byte[] hashI = Raw(payloads, IsakmpPayloadType.Hash);

                byte[] expectedHashI = IkeV1Auth.ComputeHashI(
                    _prf, _keys!.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, idiBody);
                Assert.Equal(expectedHashI, hashI); // the client authenticated correctly

                byte[] idrBody = IdBody(IdTypeIpv4, 0, 0, IPAddress.Parse("10.0.0.1").GetAddressBytes());
                byte[] hashR = IkeV1Auth.ComputeHashR(
                    _prf, _keys.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, idrBody);

                var inner = new List<IsakmpPayload>
                {
                    new IsakmpRawPayload(IsakmpPayloadType.Identification, idrBody),
                    new IsakmpRawPayload(IsakmpPayloadType.Hash, hashR),
                };
                byte[] mm6 = EncodeEncrypted(_phase1Cipher!, IsakmpExchangeType.MainMode, 0, inner);
                _phase1LastIv = _phase1Cipher!.CurrentIv; // seeds every later derived-IV (QM / Informational) cipher
                return mm6;
            }

            // ---- Quick Mode ----

            /// <summary>QM1: decrypt with the derived QM IV, capture the client's ESP SPI + Ni, build QM2 (HASH(2)+SA+Nr).</summary>
            public byte[] HandleQuickMode1(byte[] qm1)
            {
                _quickModeId = IsakmpMessage.Decode(qm1).MessageId; // header is in the clear even when encrypted
                _quickModeCipher = NewQuickModeCipher(_quickModeId);

                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher, qm1);
                IsakmpSaPayload sa = payloads.OfType<IsakmpSaPayload>().First();
                ChildOutboundSpi = sa.Proposals[0].Spi; // the client's inbound ESP SPI; our outbound
                _quickModeNonceInitiator = Raw(payloads, IsakmpPayloadType.Nonce);

                // The payloads after HASH(2) on the wire, in order: SA(ESP, our SPI) then Nr.
                var afterHash = new List<IsakmpPayload>
                {
                    IkeV1Proposals.Phase2(ChildInboundSpi),
                    new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder),
                };
                byte[] afterHashBytes = EncodeChain(afterHash);
                byte[] hash2 = IkeV1QuickMode.ComputeHash2(
                    _prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, afterHashBytes);

                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash2) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(_quickModeCipher, IsakmpExchangeType.QuickMode, _quickModeId, inner);
            }

            /// <summary>QM3: decrypt with the same QM cipher (IV advanced) and verify HASH(3).</summary>
            public void HandleQuickMode3(byte[] qm3)
            {
                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher!, qm3);
                byte[] hash3 = Raw(payloads, IsakmpPayloadType.Hash);
                byte[] expected = IkeV1QuickMode.ComputeHash3(
                    _prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, _nonceResponder);
                Assert.Equal(expected, hash3);
            }

            /// <summary>Derives the ESP CHILD SA keys (AES-256 + HMAC-SHA1), mirroring the client's SPI orientation.</summary>
            public IkeV1Phase2Keys CreatePhase2Keys()
                => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                    ChildInboundSpi, ChildOutboundSpi, _quickModeNonceInitiator, _nonceResponder,
                    encryptionKeyLength: 32, integrityKeyLength: 20);

            // ---- Informational (DPD / Delete) ----

            /// <summary>Decrypts an Informational message and returns the DPD notify (type, sequence) it carries.</summary>
            public (ushort, uint) ReadDpdNotify(byte[] wire)
            {
                List<IsakmpPayload> payloads = DecryptInformational(wire);
                byte[] notifyBody = Raw(payloads, IsakmpPayloadType.Notification);
                Assert.True(IkeV1Dpd.TryParseNotify(notifyBody, out ushort notifyType, out uint sequence));
                return (notifyType, sequence);
            }

            /// <summary>Builds an encrypted DPD R-U-THERE-ACK the way the client's ProcessInformational expects it.</summary>
            public byte[] BuildDpdAck(uint sequence)
            {
                uint messageId = 0x55667788;
                byte[] notifyBody = IkeV1Dpd.BuildNotifyBody(_cookieI, _cookieR, IkeV1Dpd.RUThereAck, sequence);
                var afterHash = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Notification, notifyBody) };
                byte[] hash = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, messageId, EncodeChain(afterHash));

                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(NewQuickModeCipher(messageId), IsakmpExchangeType.Informational, messageId, inner);
            }

            /// <summary>Decrypts an Informational message and returns the protocol of the Delete payload it carries.</summary>
            public byte ReadDeleteProtocol(byte[] wire)
            {
                List<IsakmpPayload> payloads = DecryptInformational(wire);
                byte[] deleteBody = Raw(payloads, IsakmpPayloadType.Delete);
                return deleteBody[4]; // Delete body: DOI(4) | Protocol(1) | …
            }

            List<IsakmpPayload> DecryptInformational(byte[] wire)
            {
                uint messageId = IsakmpMessage.Decode(wire).MessageId;
                return DecryptChain(NewQuickModeCipher(messageId), wire);
            }

            // A QM / Informational message derives its IV from the last Phase-1 IV and its message id (RFC 2409 §5.5).
            IkeV1Cipher NewQuickModeCipher(uint messageId)
                => new IkeV1Cipher(_keys!.CipherKey, IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId));

            // ---- hand-rolled ISAKMP framing (codec chain helpers are internal) ----

            byte[] EncodeClear(IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
            {
                byte[] body = EncodeChain(payloads);
                return Frame(exchange, IsakmpFlags.None, messageId, payloads[0].Type, body);
            }

            byte[] EncodeEncrypted(IkeV1Cipher cipher, IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
            {
                byte[] ciphertext = cipher.Encrypt(EncodeChain(payloads));
                return Frame(exchange, IsakmpFlags.Encryption, messageId, payloads[0].Type, ciphertext);
            }

            byte[] Frame(IsakmpExchangeType exchange, IsakmpFlags flags, uint messageId, IsakmpPayloadType firstPayload, byte[] body)
            {
                int totalLength = IsakmpMessage.HeaderSize + body.Length;
                byte[] wire = new byte[totalLength];
                Buffer.BlockCopy(_cookieI, 0, wire, 0, 8);
                Buffer.BlockCopy(_cookieR, 0, wire, 8, 8);
                wire[16] = (byte)firstPayload;
                wire[17] = IsakmpMessage.Version10;
                wire[18] = (byte)exchange;
                wire[19] = (byte)flags;
                wire[20] = (byte)(messageId >> 24); wire[21] = (byte)(messageId >> 16);
                wire[22] = (byte)(messageId >> 8); wire[23] = (byte)messageId;
                wire[24] = (byte)(totalLength >> 24); wire[25] = (byte)(totalLength >> 16);
                wire[26] = (byte)(totalLength >> 8); wire[27] = (byte)totalLength;
                Buffer.BlockCopy(body, 0, wire, IsakmpMessage.HeaderSize, body.Length);
                return wire;
            }

            static byte[] EncodeChain(List<IsakmpPayload> payloads)
            {
                var output = new List<byte>();
                for (int i = 0; i < payloads.Count; i++)
                {
                    IsakmpPayloadType next = i + 1 < payloads.Count ? payloads[i + 1].Type : IsakmpPayloadType.None;
                    int start = output.Count;
                    output.Add((byte)next);
                    output.Add(0);          // reserved
                    output.Add(0); output.Add(0); // length placeholder (filled below)
                    payloads[i].WriteBody(output);
                    int length = output.Count - start;
                    output[start + 2] = (byte)(length >> 8);
                    output[start + 3] = (byte)length;
                }
                return output.ToArray();
            }

            // The SA-payload parser (IsakmpSaPayload.Parse) is internal, so to parse a decrypted chain we re-frame the
            // plaintext as a cleartext ISAKMP message (header + body, no Encryption flag) and use the public
            // IsakmpMessage.Decode, which drives the real codec — including the SA payload parser — for us.
            List<IsakmpPayload> ParseChain(byte[] body, IsakmpPayloadType firstType)
            {
                byte[] cleartext = Frame(IsakmpExchangeType.QuickMode, IsakmpFlags.None, 0, firstType, body);
                return IsakmpMessage.Decode(cleartext).Payloads;
            }

            List<IsakmpPayload> DecryptChain(IkeV1Cipher cipher, byte[] wire)
            {
                var firstType = (IsakmpPayloadType)wire[16];
                byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
                Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
                byte[] plain = cipher.Decrypt(ciphertext);
                return ParseChain(plain, firstType);
            }

            static byte[] Raw(List<IsakmpPayload> payloads, IsakmpPayloadType type)
                => payloads.OfType<IsakmpRawPayload>().First(p => p.Type == type).Body;

            static byte[] IdBody(byte idType, byte protocol, ushort port, byte[] address)
            {
                byte[] body = new byte[4 + address.Length];
                body[0] = idType;
                body[1] = protocol;
                body[2] = (byte)(port >> 8);
                body[3] = (byte)port;
                Buffer.BlockCopy(address, 0, body, 4, address.Length);
                return body;
            }
        }
    }
}
