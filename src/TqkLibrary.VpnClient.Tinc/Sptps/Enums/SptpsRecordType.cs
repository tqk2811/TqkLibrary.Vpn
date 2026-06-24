namespace TqkLibrary.VpnClient.Tinc.Sptps.Enums
{
    /// <summary>
    /// SPTPS record <c>type</c> byte. Values 0–127 carry application data (for the meta connection these are tinc
    /// request lines); 128 and above are control records (RFC-like reserved range).
    /// </summary>
    public enum SptpsRecordType : byte
    {
        /// <summary>Handshake record (KEX / SIG / ACK payloads), <c>SPTPS_HANDSHAKE</c>.</summary>
        Handshake = 128,

        /// <summary>Fatal alert record, <c>SPTPS_ALERT</c>.</summary>
        Alert = 129,

        /// <summary>Orderly close record, <c>SPTPS_CLOSE</c>.</summary>
        Close = 130,
    }
}
