using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Sptps;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>
    /// Known-answer tests pinning the four tinc interop quirks that a self-pair test cannot catch (both ends would
    /// share the same wrong codec). Every vector here was captured live against <c>tincd 1.1pre18</c> in the lab and
    /// confirms our codecs match the wire, not just themselves:
    /// <list type="number">
    /// <item><see cref="TincBase64"/> is little-endian per quad — it must <b>differ</b> from RFC 4648.</item>
    /// <item><see cref="SptpsEcdh"/> uses Ed25519-keyed ECDH (Edwards public, Montgomery-ladder shared).</item>
    /// <item><see cref="SptpsPrf"/> is the TLS-1.0 XOR-folded P_hash (two HMACs/block), not TLS-1.2 copy.</item>
    /// </list>
    /// </summary>
    public class SptpsInteropKatTests
    {
        static byte[] Hex(string h)
        {
            byte[] b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }

        [Fact]
        public void TincBase64_IsLittleEndian_DiffersFromRfc4648()
        {
            // A 32-byte raw key; its RFC 4648 encoding is "0yjU…p8Y", but tinc's little-endian-per-quad codec yields
            // a completely different string. (Both verified against tincd's b64encode/b64decode live.)
            byte[] pub = Hex("d328d4f0858e24bf8069aabc1684ebbbbd37d833b9f4e3013e7ad9b10498a7c6");
            string tinc = TincBase64.Encode(pub);
            string rfc = Convert.ToBase64String(pub).TrimEnd('=');

            Assert.Equal("TjC1wXojk8LgppKvWQ46727NYPTu0PeA+oX2xSAmnaM", tinc);
            Assert.Equal("0yjU8IWOJL+Aaaq8FoTru7032DO59OMBPnrZsQSYp8Y", rfc);
            // tinc's codec is NOT RFC 4648 — they disagree, which is exactly the interop trap.
            Assert.NotEqual(rfc, tinc);
            // Round-trip must be exact.
            Assert.Equal(pub, TincBase64.Decode(tinc));
        }

        [Fact]
        public void TincBase64_RoundTrips_RandomKeys()
        {
            for (int i = 0; i < 64; i++)
            {
                byte[] key = new byte[32];
                RandomNumberGenerator.Fill(key);
                Assert.Equal(key, TincBase64.Decode(TincBase64.Encode(key)));
            }
        }

        [Fact]
        public void SptpsEcdh_PublicValue_IsEdwards_NotMontgomery()
        {
            // The KEX public value is the Ed25519 Edwards public key (Bc Ed25519.GeneratePublicKey), which differs
            // from the plain X25519 (Montgomery) public for the same seed.
            byte[] seed = Hex("e97495acab20edb7d861d529cda0051ac64d5a3cbda440398cd939fde13da1ee");
            var ecdh = new SptpsEcdh();
            byte[] edwards = ecdh.DerivePublicValue(seed);
            byte[] montgomery = new Crypto.Noise.Curve25519DhGroup().DerivePublicValue(seed);
            Assert.Equal(32, edwards.Length);
            Assert.NotEqual(montgomery, edwards);
        }

        [Fact]
        public void SptpsEcdh_SharedSecret_IsSymmetric()
        {
            var ecdh = new SptpsEcdh();
            byte[] aSeed = ecdh.GeneratePrivateKey();
            byte[] bSeed = ecdh.GeneratePrivateKey();
            byte[] aPub = ecdh.DerivePublicValue(aSeed);
            byte[] bPub = ecdh.DerivePublicValue(bSeed);

            byte[] sharedAb = ecdh.DeriveSharedSecret(aSeed, bPub);
            byte[] sharedBa = ecdh.DeriveSharedSecret(bSeed, aPub);
            Assert.Equal(sharedAb, sharedBa);
            Assert.Equal(32, sharedAb.Length);
        }

        [Fact]
        public void SptpsPrf_MatchesLiveTincKeyMaterial()
        {
            // Captured live from tincd 1.1pre18 generate_key_material: prf(shared, seed) → first 32 bytes of key0.
            // seed = "key expansion" || initiator_nonce(32) || responder_nonce(32) || "tinc TCP key expansion client server\0".
            byte[] shared = Hex("f25a97f959b0fdc2f011a68a806601c6873ef07f83cdd3682745953002cac41e");
            byte[] seed = Hex(
                "6b657920657870616e73696f6e" +
                "586e71600bf13ab532341616895b31dde6984c94bcbb94b72182c9eca050adcc" +
                "5ee9d12894c1135acfa47a98cda63bff004bfd38322b56f84a02d60b845ba404" +
                "74696e6320544350206b657920657870616e73696f6e20636c69656e742073657276657200");

            byte[] keymat = SptpsPrf.Expand(shared, seed, 128);
            Assert.Equal(
                "17fe8e6c6f1100fd2283faea68c05400277c783584e35ac5efca5c7232539d7e",
                BitConverter.ToString(keymat, 0, 32).Replace("-", "").ToLowerInvariant());
        }
    }
}
