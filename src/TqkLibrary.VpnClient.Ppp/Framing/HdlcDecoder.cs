namespace TqkLibrary.VpnClient.Ppp.Framing
{
    /// <summary>
    /// Streaming decoder for HDLC-async PPP (RFC 1662). Feed arbitrary byte chunks via <see cref="Push"/>;
    /// it un-stuffs, splits on 0x7E flags, verifies the FCS-16, and raises each valid frame's content.
    /// </summary>
    public sealed class HdlcDecoder
    {
        readonly List<byte> _buffer = new(256);
        bool _escaped;

        /// <summary>Raised for each frame whose FCS verifies; argument is the content (without flags/FCS).</summary>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <summary>Pushes a chunk of received bytes through the decoder.</summary>
        public void Push(ReadOnlySpan<byte> data)
        {
            foreach (byte b in data)
            {
                if (b == HdlcFramer.Flag)
                {
                    if (_buffer.Count > 0)
                        TryComplete();
                    _buffer.Clear();
                    _escaped = false;
                    continue;
                }

                if (b == HdlcFramer.ControlEscape)
                {
                    _escaped = true;
                    continue;
                }

                _buffer.Add(_escaped ? (byte)(b ^ 0x20) : b);
                _escaped = false;
            }
        }

        void TryComplete()
        {
            // Need at least the 2-byte FCS.
            if (_buffer.Count < 3) return;

            int contentLen = _buffer.Count - 2;
            byte[] raw = _buffer.ToArray();
            ReadOnlySpan<byte> content = raw.AsSpan(0, contentLen);
            ushort received = (ushort)(raw[contentLen] | (raw[contentLen + 1] << 8));
            if (Fcs16.Compute(content) != received)
                return; // bad FCS -> drop silently

            FrameReceived?.Invoke(content.ToArray());
        }
    }
}
