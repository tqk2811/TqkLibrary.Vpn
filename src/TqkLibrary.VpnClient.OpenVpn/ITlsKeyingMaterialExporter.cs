namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Exports keying material from an established TLS session per <b>RFC 5705</b> (the TLS keying-material exporter).
    /// OpenVPN's <c>--key-derivation tls-ekm</c> mode (IV_PROTO bit <see cref="DataChannel.OpenVpnPeerInfo.IvProtoTlsKeyExport"/>)
    /// derives the data-channel keys straight from this exporter — over label <c>"EXPORTER-OpenVPN-datakeys"</c> — instead of
    /// the classic key-method-2 PRF blend of the exchanged <c>key_source2</c> randoms
    /// (see <see cref="DataChannel.OpenVpnKeyMethod2.DeriveKey2"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Scaffold only (roadmap F.5).</b> This is an unimplemented seam. The default TLS engine on the control channel is
    /// <see cref="System.Net.Security.SslStream"/>, which <b>does not</b> expose an RFC 5705 exporter on
    /// <c>netstandard2.0</c> or <c>net8.0</c>: <c>SslStream.ExportKeyingMaterial(...)</c> was only added in <b>.NET 9</b>
    /// (verified by reflection — net8 <see cref="System.Net.Security.SslStream"/> has no <c>Export*</c>/<c>Keying</c> member).
    /// </para>
    /// <para>
    /// Until the project either targets .NET 9+ or routes the control-channel TLS through <b>BouncyCastle TLS</b>
    /// (<c>Org.BouncyCastle.Tls.TlsContext.ExportKeyingMaterial</c>), <c>tls-ekm</c> stays unimplemented and the client
    /// keeps using key-method-2 (the legacy PRF derivation). Wiring an implementation requires a real TLS handshake under
    /// test, which is out of scope for the offline F.5a slice — hence this contract is declared but not yet realized.
    /// </para>
    /// </remarks>
    public interface ITlsKeyingMaterialExporter
    {
        /// <summary>
        /// Returns <paramref name="length"/> bytes of exporter output (RFC 5705) for <paramref name="label"/> with an
        /// optional <paramref name="context"/> (OpenVPN <c>tls-ekm</c> uses an empty context). Implementations bind to the
        /// finished TLS session; calling before the handshake completes is invalid.
        /// </summary>
        byte[] Export(string label, ReadOnlySpan<byte> context, int length);
    }
}
