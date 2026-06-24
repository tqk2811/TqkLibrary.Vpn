namespace TqkLibrary.VpnClient.Tinc.Sptps.Enums
{
    /// <summary>Outcome of decoding one SPTPS stream record from a buffer.</summary>
    public enum SptpsDecodeResult
    {
        /// <summary>A full record was decoded.</summary>
        Ok,

        /// <summary>The buffer does not yet contain a whole record; read more bytes and retry.</summary>
        NeedMore,

        /// <summary>An encrypted record failed authentication (forged or out-of-sync).</summary>
        AuthFailed,
    }
}
