using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Models;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>
    /// The initiator-side IKEv2 client for PSK authentication: drives IKE_SA_INIT then IKE_AUTH, verifies the
    /// responder's AUTH, and exposes the negotiated CHILD_SA SPIs and keys for the ESP data plane to consume.
    /// Pure protocol logic — the caller owns the UDP transport.
    /// </summary>
    public sealed class IkeClient
    {
        readonly HmacPrf _prf = HmacPrf.Sha256();
        readonly IkeSaInitiator _initiator;
        readonly byte[] _preSharedKey;
        readonly IdentificationPayload _identity;
        readonly bool _requestTransportMode;

        IkeCipher? _cipher;

        /// <summary>Creates a client with the given PSK and IDi, optionally requesting ESP transport mode (for L2TP).</summary>
        public IkeClient(byte[] preSharedKey, IdentificationPayload identity, bool requestTransportMode = true, byte[]? initiatorSpi = null)
        {
            _preSharedKey = preSharedKey;
            _identity = identity;
            _requestTransportMode = requestTransportMode;
            _initiator = new IkeSaInitiator(initiatorSpi);
            ChildInboundSpi = RandomSpi();
        }

        /// <summary>The ESP SPI we chose (the peer uses it when sending to us).</summary>
        public byte[] ChildInboundSpi { get; }

        /// <summary>The ESP SPI the responder chose (we use it when sending to the peer).</summary>
        public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

        /// <summary>The CHILD_SA keys, valid after a successful <see cref="ProcessAuthResponse"/>.</summary>
        public ChildSaKeys? ChildKeys { get; private set; }

        /// <summary>The IKE SA key material (after IKE_SA_INIT).</summary>
        public IkeKeyMaterial? IkeKeys => _initiator.Keys;

        /// <summary>Builds the IKE_SA_INIT request (caller encodes &amp; sends it).</summary>
        public IkeMessage BuildInitRequest(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
            => _initiator.BuildInitRequest(localIp, localPort, remoteIp, remotePort);

        /// <summary>Processes the IKE_SA_INIT response, deriving the IKE SA keys and preparing the SK cipher.</summary>
        public void ProcessInitResponse(IkeMessage response)
        {
            IkeKeyMaterial keys = _initiator.ProcessInitResponse(response);
            _cipher = IkeCipher.ForInitiator(keys);
        }

        /// <summary>Builds the encrypted IKE_AUTH request (IDi, AUTH, SAi2, TSi, TSr [, USE_TRANSPORT_MODE]).</summary>
        public byte[] BuildAuthRequest()
        {
            if (_cipher is null || _initiator.Keys is null)
                throw new InvalidOperationException("IKE_SA_INIT must complete before IKE_AUTH.");

            byte[] auth = IkePskAuth.ComputeInitiatorAuth(
                _prf, _preSharedKey, _initiator.InitRequestBytes, _initiator.PeerNonce,
                _initiator.Keys.SkPi, _identity.BodyBytes());

            var message = new IkeMessage
            {
                InitiatorSpi = _initiator.InitiatorSpi,
                ResponderSpi = _initiator.ResponderSpi,
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 1,
            };
            message.Payloads.Add(_identity);
            message.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = auth });

            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.DefaultEsp(ChildInboundSpi));
            message.Payloads.Add(sa);
            message.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
            message.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
            if (_requestTransportMode)
                message.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));

            return _cipher.EncryptMessage(message);
        }

        /// <summary>
        /// Decrypts and validates the IKE_AUTH response: verifies the responder AUTH, records its ESP SPI, and
        /// derives the CHILD_SA keys. Returns false if decryption, AUTH verification, or the SAr2 is invalid.
        /// </summary>
        public bool ProcessAuthResponse(byte[] wire)
        {
            if (_cipher is null || _initiator.Keys is null) return false;

            IkeMessage? response = _cipher.DecryptMessage(wire);
            if (response is null) return false;

            IdentificationPayload? idR = response.Payloads.OfType<IdentificationPayload>().FirstOrDefault(p => !p.IsInitiator);
            AuthenticationPayload? auth = response.Find<AuthenticationPayload>();
            SecurityAssociationPayload? sa = response.Find<SecurityAssociationPayload>();
            if (idR is null || auth is null || sa is null) return false;

            byte[] expected = IkePskAuth.ComputeResponderAuth(
                _prf, _preSharedKey, _initiator.InitResponseBytes, _initiator.Nonce,
                _initiator.Keys.SkPr, idR.BodyBytes());
            if (!FixedTimeEquals(expected, auth.Data)) return false;

            IkeProposal? proposal = sa.Proposals.FirstOrDefault();
            if (proposal is null || proposal.Spi.Length == 0) return false;
            ChildOutboundSpi = proposal.Spi;

            ChildKeys = ChildSaKeys.DeriveDefault(_initiator.Keys.SkD, _initiator.Nonce, _initiator.PeerNonce);
            return true;
        }

        static byte[] RandomSpi()
        {
            byte[] spi = new byte[4];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(spi);
            return spi;
        }

        static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
