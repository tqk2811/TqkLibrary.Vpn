using TqkLibrary.Vpn.Ppp.Enums;
using TqkLibrary.Vpn.Ppp.Models;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// Generic PPP option-negotiation state machine shared by LCP and IPCP (RFC 1661 §4, simplified for a
    /// voluntary client). Reaches <see cref="PppNegotiationState.Opened"/> once our request is acked AND we
    /// have acked the peer's request.
    /// </summary>
    public abstract class PppNegotiator
    {
        readonly Action<byte[]> _send;
        byte _nextId = 1;
        byte _lastRequestId;
        bool _localAcked;
        bool _peerAcked;

        /// <summary>Creates a negotiator that emits control packets through <paramref name="send"/>.</summary>
        protected PppNegotiator(Action<byte[]> send)
        {
            _send = send;
        }

        /// <summary>Current negotiation state.</summary>
        public PppNegotiationState State { get; private set; } = PppNegotiationState.Closed;

        /// <summary>Raised once when the negotiator reaches <see cref="PppNegotiationState.Opened"/>.</summary>
        public event Action? Opened;

        /// <summary>Sends the first Configure-Request to begin negotiation.</summary>
        public void Start()
        {
            State = PppNegotiationState.RequestSent;
            SendConfigureRequest();
        }

        /// <summary>Feeds one received control packet (Code/Id/Length + options) into the state machine.</summary>
        public void HandlePacket(ReadOnlySpan<byte> packet)
        {
            PppControlPacket parsed = PppControlCodec.Parse(packet);
            List<PppOption> options = PppControlCodec.ParseOptions(parsed.Data);

            switch ((PppCode)parsed.Code)
            {
                case PppCode.ConfigureRequest:
                    HandlePeerRequest(parsed.Identifier, options);
                    break;
                case PppCode.ConfigureAck:
                    if (parsed.Identifier == _lastRequestId)
                    {
                        _localAcked = true;
                        CheckOpened();
                    }
                    break;
                case PppCode.ConfigureNak:
                    OnNak(options);
                    SendConfigureRequest();
                    break;
                case PppCode.ConfigureReject:
                    OnReject(options);
                    SendConfigureRequest();
                    break;
            }
        }

        void SendConfigureRequest()
        {
            _lastRequestId = _nextId++;
            _send(PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, _lastRequestId, BuildLocalOptions()));
        }

        void HandlePeerRequest(byte identifier, List<PppOption> peerOptions)
        {
            (byte code, IReadOnlyList<PppOption> responseOptions) = EvaluatePeerRequest(peerOptions);
            _send(PppControlCodec.BuildConfigure(code, identifier, responseOptions));
            if (code == (byte)PppCode.ConfigureAck)
            {
                _peerAcked = true;
                CheckOpened();
            }
        }

        void CheckOpened()
        {
            if (_localAcked && _peerAcked && State != PppNegotiationState.Opened)
            {
                State = PppNegotiationState.Opened;
                Opened?.Invoke();
            }
        }

        /// <summary>The options to request for ourselves (rebuilt on each Configure-Request, after any Nak/Reject).</summary>
        protected abstract IReadOnlyList<PppOption> BuildLocalOptions();

        /// <summary>Decides our response to the peer's Configure-Request: Ack (echo), Nak (suggest), or Reject.</summary>
        protected abstract (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions);

        /// <summary>Applies the peer's Nak hints to our local options before resending.</summary>
        protected virtual void OnNak(List<PppOption> nakOptions) { }

        /// <summary>Drops options the peer rejected before resending.</summary>
        protected virtual void OnReject(List<PppOption> rejectedOptions) { }
    }
}
