namespace TqkLibrary.VpnClient.Abstractions.Transport.Interfaces
{
    /// <summary>
    /// A TLS byte stream that can additionally export keying material from its finished session per <b>RFC 5705</b>
    /// (the TLS keying-material exporter). The BCL <see cref="System.Net.Security.SslStream"/> exposes no such API on
    /// <c>netstandard2.0</c>/<c>net8.0</c> (<c>SslStream.ExportKeyingMaterial</c> was only proposed for a later .NET), so
    /// only a BouncyCastle-backed TLS stream (<c>Transport.Tls.BouncyCastleTlsByteStream</c>) implements this — wherever a
    /// protocol derives a secondary key from the control-channel TLS session.
    /// <para>
    /// First consumer: the OpenConnect (V.5) <b>DTLS 1.2 PSK</b> data path, whose pre-shared key is 32 bytes exported
    /// from the CSTP control-channel TLS session over the label <c>"EXPORTER-openconnect-psk"</c> with an empty context
    /// (draft-mavrogiannopoulos-openconnect). The same contract also fits OpenVPN's <c>tls-ekm</c>
    /// (<c>"EXPORTER-OpenVPN-datakeys"</c>) when that driver moves onto a BouncyCastle control channel.
    /// </para>
    /// </summary>
    public interface ITlsKeyingMaterialExporter
    {
        /// <summary>
        /// Returns <paramref name="length"/> bytes of RFC 5705 exporter output for <paramref name="label"/> with the
        /// optional <paramref name="context"/> (pass an empty span for no context). Valid only after the TLS handshake
        /// has completed; calling earlier throws.
        /// </summary>
        byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length);
    }
}
