namespace TqkLibrary.VpnClient.OpenVpn.Config
{
    /// <summary>
    /// A certificate/key reference from a .ovpn profile, which OpenVPN allows either as a file path
    /// (<c>ca ca.crt</c>) or inline between tags (<c>&lt;ca&gt;…&lt;/ca&gt;</c>). The parser does no file I/O — it
    /// keeps the inline PEM verbatim or records the referenced <see cref="FilePath"/> for the caller to load.
    /// </summary>
    public sealed class OpenVpnFileOrInline
    {
        /// <summary>The PEM/key text when the profile embedded it inline; null when a file path was given.</summary>
        public string? Inline { get; set; }

        /// <summary>The referenced file path when the profile pointed at a file; null when the material was inline.</summary>
        public string? FilePath { get; set; }

        /// <summary>True when the material is embedded inline (already available without loading a file).</summary>
        public bool IsInline => Inline != null;
    }
}
