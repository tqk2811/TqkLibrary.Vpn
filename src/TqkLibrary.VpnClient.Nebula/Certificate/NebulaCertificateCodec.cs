using TqkLibrary.VpnClient.Nebula.Certificate.Enums;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;

namespace TqkLibrary.VpnClient.Nebula.Certificate
{
    /// <summary>
    /// Encodes and decodes Nebula v1 certificates (<c>RawNebulaCertificate</c> / <c>RawNebulaCertificateDetails</c>,
    /// cert_v1.proto) on the protobuf wire format. The signing-critical method is <see cref="MarshalDetails"/>: it
    /// reproduces, byte-for-byte, the proto3 marshalling of the details that the CA signed (fields in ascending
    /// number, default values omitted), so the recombined details verify against the certificate signature.
    /// <para>
    /// Field numbers — Details: Name=1, Ips=2(packed), Subnets=3(packed), Groups=4(repeated), NotBefore=5,
    /// NotAfter=6, PublicKey=7, IsCA=8, Issuer=9, Curve=100. Certificate: Details=1, Signature=2.
    /// </para>
    /// </summary>
    public sealed class NebulaCertificateCodec
    {
        const int FieldName = 1;
        const int FieldIps = 2;
        const int FieldSubnets = 3;
        const int FieldGroups = 4;
        const int FieldNotBefore = 5;
        const int FieldNotAfter = 6;
        const int FieldPublicKey = 7;
        const int FieldIsCa = 8;
        const int FieldIssuer = 9;
        const int FieldCurve = 100;

        const int CertDetails = 1;
        const int CertSignature = 2;

        /// <summary>
        /// Marshals the certificate details exactly as proto3 would (the bytes the CA signs). Default values are
        /// omitted: an empty/false/zero field is not written, and Curve25519 (curve value 0) is left off.
        /// </summary>
        public byte[] MarshalDetails(NebulaCertificateDetails details)
        {
            if (details is null) throw new ArgumentNullException(nameof(details));
            var w = new ProtobufWriter();

            // proto3: a default scalar (empty string / zero / false / empty bytes) is not serialised.
            if (details.Name.Length != 0) w.WriteStringField(FieldName, details.Name);
            w.WritePackedUInt32Field(FieldIps, details.Ips);
            w.WritePackedUInt32Field(FieldSubnets, details.Subnets);
            foreach (string g in details.Groups) w.WriteStringField(FieldGroups, g);
            if (details.NotBefore != 0) w.WriteInt64Field(FieldNotBefore, details.NotBefore);
            if (details.NotAfter != 0) w.WriteInt64Field(FieldNotAfter, details.NotAfter);
            if (details.PublicKey.Length != 0) w.WriteLengthDelimitedField(FieldPublicKey, details.PublicKey);
            if (details.IsCa) w.WriteVarintField(FieldIsCa, 1);
            if (details.Issuer.Length != 0) w.WriteLengthDelimitedField(FieldIssuer, details.Issuer);
            if (details.Curve != NebulaCurve.Curve25519) w.WriteVarintField(FieldCurve, (ulong)details.Curve);

            return w.ToArray();
        }

        /// <summary>Parses certificate details from their protobuf encoding (unknown fields are skipped).</summary>
        public NebulaCertificateDetails UnmarshalDetails(ReadOnlySpan<byte> data)
        {
            var d = new NebulaCertificateDetails();
            var r = new ProtobufReader(data);
            while (r.TryReadTag(out int field, out int wireType))
            {
                switch (field)
                {
                    case FieldName when wireType == 2:
                        d.Name = System.Text.Encoding.UTF8.GetString(r.ReadLengthDelimited().ToArray());
                        break;
                    case FieldIps when wireType == 2:
                        ReadPackedUInt32(r.ReadLengthDelimited(), d.Ips);
                        break;
                    case FieldSubnets when wireType == 2:
                        ReadPackedUInt32(r.ReadLengthDelimited(), d.Subnets);
                        break;
                    case FieldGroups when wireType == 2:
                        d.Groups.Add(System.Text.Encoding.UTF8.GetString(r.ReadLengthDelimited().ToArray()));
                        break;
                    case FieldNotBefore when wireType == 0:
                        d.NotBefore = unchecked((long)r.ReadVarint());
                        break;
                    case FieldNotAfter when wireType == 0:
                        d.NotAfter = unchecked((long)r.ReadVarint());
                        break;
                    case FieldPublicKey when wireType == 2:
                        d.PublicKey = r.ReadLengthDelimited().ToArray();
                        break;
                    case FieldIsCa when wireType == 0:
                        d.IsCa = r.ReadVarint() != 0;
                        break;
                    case FieldIssuer when wireType == 2:
                        d.Issuer = r.ReadLengthDelimited().ToArray();
                        break;
                    case FieldCurve when wireType == 0:
                        d.Curve = (NebulaCurve)r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wireType);
                        break;
                }
            }
            return d;
        }

        /// <summary>Marshals a full certificate (details sub-message + signature).</summary>
        public byte[] MarshalCertificate(NebulaCertificate certificate)
        {
            if (certificate is null) throw new ArgumentNullException(nameof(certificate));
            var w = new ProtobufWriter();
            w.WriteLengthDelimitedField(CertDetails, MarshalDetails(certificate.Details));
            if (certificate.Signature.Length != 0) w.WriteLengthDelimitedField(CertSignature, certificate.Signature);
            return w.ToArray();
        }

        /// <summary>
        /// Parses a full certificate, retaining the raw bytes of the details sub-message in
        /// <paramref name="signedDetails"/> so the signature can be verified against the exact bytes that were signed
        /// (rather than a re-marshalled copy, which must but might not be identical).
        /// </summary>
        public NebulaCertificate UnmarshalCertificate(ReadOnlySpan<byte> data, out byte[] signedDetails)
        {
            var cert = new NebulaCertificate();
            signedDetails = Array.Empty<byte>();
            var r = new ProtobufReader(data);
            while (r.TryReadTag(out int field, out int wireType))
            {
                switch (field)
                {
                    case CertDetails when wireType == 2:
                        signedDetails = r.ReadLengthDelimited().ToArray();
                        cert.Details = UnmarshalDetails(signedDetails);
                        break;
                    case CertSignature when wireType == 2:
                        cert.Signature = r.ReadLengthDelimited().ToArray();
                        break;
                    default:
                        r.SkipField(wireType);
                        break;
                }
            }
            return cert;
        }

        static void ReadPackedUInt32(ReadOnlySpan<byte> block, List<uint> destination)
        {
            var r = new ProtobufReader(block);
            while (r.HasMore) destination.Add((uint)r.ReadVarint());
        }
    }
}
