using Org.BouncyCastle.Tls;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// Optional hook to validate (or pin) the DTLS server's certificate chain during the handshake. It is the DTLS
    /// analogue of <see cref="System.Net.Security.RemoteCertificateValidationCallback"/> used by the TLS byte streams,
    /// but receives BouncyCastle's <see cref="TlsServerCertificate"/> (since the handshake runs through BouncyCastle, not
    /// <c>SslStream</c>). Return <c>true</c> to accept the certificate or <c>false</c> to abort the handshake with a
    /// fatal alert. When no callback is supplied the certificate is accepted (the OpenConnect cookie still authorises the
    /// tunnel; production callers should pin/validate the gateway certificate here).
    /// </summary>
    /// <param name="serverCertificate">The certificate chain the server presented; <c>Certificate.Length</c> is 0 when none was sent.</param>
    /// <returns><c>true</c> to accept; <c>false</c> to reject and tear the handshake down.</returns>
    public delegate bool DtlsServerCertificateValidationCallback(TlsServerCertificate serverCertificate);
}
