using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.L2tp;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec
{
    /// <summary>
    /// Carries L2TP messages over IPsec: each L2TP datagram is wrapped in UDP/1701 and ESP-protected (transport
    /// mode), then handed to the UDP/4500 sender; inbound ESP packets are decrypted, the UDP/1701 payload is
    /// extracted, and the L2TP message is surfaced. This is the ESP data plane, identical for IKEv1 or IKEv2.
    /// </summary>
    public sealed class IpsecL2tpTransport : IL2tpTransport
    {
        // High-watermark on the 2^32 outbound ESP sequence space: at ~75% we ask the driver to rekey, leaving ~1.07B
        // packets of headroom for the Quick Mode round-trip to finish before the counter would overflow (RFC 4303 §3.3.3).
        const uint DefaultRekeyThreshold = 0xC000_0000u;
        // If a rekey hasn't installed a fresh SA, re-raise RekeyNeeded every ~1M further packets (≈1024 retries of headroom).
        const uint DefaultRekeyRetryStep = 0x0010_0000u;

        readonly Func<ReadOnlyMemory<byte>, Task> _sendEsp;
        readonly object _swapLock = new();
        readonly uint _rekeyThreshold;
        readonly uint _rekeyRetryStep;
        EspSession _esp;                 // current SA: outbound + primary inbound
        EspSession? _previousInbound;    // the pre-rekey SA, kept briefly so in-flight packets still decrypt
        long _rekeySignalAt;             // next outbound sequence at which to (re)raise RekeyNeeded

        /// <summary>Creates the transport over an established ESP session and an ESP datagram sink.</summary>
        /// <param name="rekeyAtSequence">Outbound sequence high-watermark that first triggers <see cref="RekeyNeeded"/>.</param>
        /// <param name="rekeyRetryStep">Packets between re-raising <see cref="RekeyNeeded"/> while no fresh SA arrives.</param>
        public IpsecL2tpTransport(EspSession esp, Func<ReadOnlyMemory<byte>, Task> sendEsp,
            uint rekeyAtSequence = DefaultRekeyThreshold, uint rekeyRetryStep = DefaultRekeyRetryStep)
        {
            _esp = esp;
            _sendEsp = sendEsp;
            _rekeyThreshold = rekeyAtSequence;
            _rekeyRetryStep = Math.Max(1u, rekeyRetryStep);
            _rekeySignalAt = rekeyAtSequence;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

        /// <summary>
        /// Raised when the outbound ESP sequence number nears exhaustion (2^32) and the SA must be rekeyed before it
        /// would wrap. The driver responds with a Quick Mode rekey; re-raised periodically until a fresh SA is
        /// installed via <see cref="SwapSession"/>, which re-arms the watermark.
        /// </summary>
        public event Action? RekeyNeeded;

        /// <summary>
        /// Installs a rekeyed ESP session: new packets go out on it immediately, while the previous SA is retained
        /// for inbound only until <see cref="DropPreviousInbound"/> (make-before-break, so no packet is lost).
        /// </summary>
        public void SwapSession(EspSession next)
        {
            lock (_swapLock)
            {
                _previousInbound = _esp;
                _esp = next;
            }
            // Fresh SA → its sequence restarts at 0, so re-arm the exhaustion watermark.
            Interlocked.Exchange(ref _rekeySignalAt, _rekeyThreshold);
        }

        /// <summary>Drops the retained pre-rekey SA once the grace period has elapsed.</summary>
        public void DropPreviousInbound()
        {
            lock (_swapLock) _previousInbound = null;
        }

        /// <inheritdoc/>
        public Task SendAsync(ReadOnlyMemory<byte> l2tpDatagram)
        {
            EspSession esp;
            lock (_swapLock) esp = _esp;
            byte[] udp = UdpEncapsulation.Build(UdpEncapsulation.L2tpPort, UdpEncapsulation.L2tpPort, l2tpDatagram.Span);
            byte[] espPacket = esp.Protect(udp, EspConstants.NextHeaderUdp);
            MaybeSignalRekey(esp.OutboundSequence);
            return _sendEsp(espPacket);
        }

        // Once the outbound sequence crosses the watermark, raise RekeyNeeded exactly once per step (CAS so concurrent
        // sends don't double-fire), advancing the next trigger so a stalled rekey is retried without spamming per packet.
        void MaybeSignalRekey(uint sequence)
        {
            long signalAt = Interlocked.Read(ref _rekeySignalAt);
            if (sequence < signalAt) return;
            long next = Math.Min(signalAt + _rekeyRetryStep, uint.MaxValue);
            if (Interlocked.CompareExchange(ref _rekeySignalAt, next, signalAt) == signalAt)
                RekeyNeeded?.Invoke();
        }

        /// <summary>Feeds one inbound ESP packet (decrypt → UDP/1701 → L2TP), raising <see cref="DatagramReceived"/>.</summary>
        public void OnEspPacket(ReadOnlyMemory<byte> espPacket)
        {
            EspSession primary;
            EspSession? previous;
            lock (_swapLock) { primary = _esp; previous = _previousInbound; }

            // SPIs are distinct per SA, so TryUnprotect on the wrong session simply fails the SPI check.
            if (!primary.TryUnprotect(espPacket.Span, out byte[] udp, out byte nextHeader)
                && (previous is null || !previous.TryUnprotect(espPacket.Span, out udp, out nextHeader)))
                return;

            if (nextHeader != EspConstants.NextHeaderUdp) return;
            if (!UdpEncapsulation.TryParse(udp, out _, out ushort destinationPort, out byte[] l2tp)) return;
            if (destinationPort != UdpEncapsulation.L2tpPort) return;
            DatagramReceived?.Invoke(l2tp);
        }
    }
}
