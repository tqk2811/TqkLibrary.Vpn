using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>
    /// Self-interop for the SPTPS handshake: an initiator and a responder built from generated Ed25519 keys complete
    /// KEX → SIG in both directions, agree on crossed directional keys, and reject a tampered or wrong-peer SIG.
    /// </summary>
    public class SptpsHandshakeTests
    {
        static (byte[] priv, byte[] pub) NewEd25519()
        {
            var signer = new Ed25519Signer();
            byte[] priv = new byte[signer.PrivateKeySizeInBytes];
            System.Security.Cryptography.RandomNumberGenerator.Fill(priv);
            byte[] pub = signer.DerivePublicKey(priv);
            return (priv, pub);
        }

        [Fact]
        public void Handshake_InitiatorResponder_DeriveCrossedKeys()
        {
            var (initPriv, initPub) = NewEd25519();
            var (respPriv, respPub) = NewEd25519();
            byte[] label = SptpsHandshake.BuildMetaLabel("client", "server");

            var init = new SptpsHandshake(true, initPriv, respPub, label);
            var resp = new SptpsHandshake(false, respPriv, initPub, label);

            byte[] initKex = init.CreateKex();
            byte[] respKex = resp.CreateKex();

            init.ConsumeKex(respKex);
            resp.ConsumeKex(initKex);

            byte[] initSig = init.CreateSig();
            byte[] respSig = resp.CreateSig();

            Assert.True(resp.ConsumeSig(initSig));
            Assert.True(init.ConsumeSig(respSig));

            // Out of one side equals In of the other (the directional keys cross).
            Assert.Equal(init.OutCipherKey, resp.InCipherKey);
            Assert.Equal(init.InCipherKey, resp.OutCipherKey);
            Assert.Equal(SptpsConstants.CipherKeySize, init.OutCipherKey.Length);
        }

        [Fact]
        public void Handshake_TamperedSig_Rejected()
        {
            var (initPriv, initPub) = NewEd25519();
            var (respPriv, respPub) = NewEd25519();
            byte[] label = SptpsHandshake.BuildMetaLabel("client", "server");

            var init = new SptpsHandshake(true, initPriv, respPub, label);
            var resp = new SptpsHandshake(false, respPriv, initPub, label);

            byte[] initKex = init.CreateKex();
            byte[] respKex = resp.CreateKex();
            init.ConsumeKex(respKex);
            resp.ConsumeKex(initKex);

            byte[] sig = init.CreateSig();
            sig[0] ^= 0xFF;
            Assert.False(resp.ConsumeSig(sig));
        }

        [Fact]
        public void Handshake_WrongPeerKey_Rejected()
        {
            var (initPriv, _) = NewEd25519();
            var (respPriv, respPub) = NewEd25519();
            var (_, otherPub) = NewEd25519(); // responder expects a different initiator key
            byte[] label = SptpsHandshake.BuildMetaLabel("client", "server");

            var init = new SptpsHandshake(true, initPriv, respPub, label);
            var resp = new SptpsHandshake(false, respPriv, otherPub, label);

            byte[] initKex = init.CreateKex();
            byte[] respKex = resp.CreateKex();
            init.ConsumeKex(respKex);
            resp.ConsumeKex(initKex);

            Assert.False(resp.ConsumeSig(init.CreateSig()));
        }

        [Fact]
        public void Handshake_MismatchedLabel_Rejected()
        {
            // The label feeds both the signed transcript and the KDF seed; a mismatch must break authentication.
            var (initPriv, initPub) = NewEd25519();
            var (respPriv, respPub) = NewEd25519();

            var init = new SptpsHandshake(true, initPriv, respPub, SptpsHandshake.BuildMetaLabel("client", "server"));
            var resp = new SptpsHandshake(false, respPriv, initPub, SptpsHandshake.BuildMetaLabel("client", "OTHER"));

            byte[] initKex = init.CreateKex();
            byte[] respKex = resp.CreateKex();
            init.ConsumeKex(respKex);
            resp.ConsumeKex(initKex);

            // Server reconstructs the transcript with its (different) label → our SIG fails to verify.
            Assert.False(resp.ConsumeSig(init.CreateSig()));
        }

        [Fact]
        public void Handshake_RecordsFlow_AfterKeysEnabled()
        {
            // Full handshake then exchange an encrypted record both ways through the record layer using the derived
            // directional keys — proves the keys orient correctly end to end (the shape of the live interop).
            var (initPriv, initPub) = NewEd25519();
            var (respPriv, respPub) = NewEd25519();
            byte[] label = SptpsHandshake.BuildMetaLabel("client", "server");

            var init = new SptpsHandshake(true, initPriv, respPub, label);
            var resp = new SptpsHandshake(false, respPriv, initPub, label);
            byte[] ik = init.CreateKex(), rk = resp.CreateKex();
            init.ConsumeKex(rk); resp.ConsumeKex(ik);
            Assert.True(resp.ConsumeSig(init.CreateSig()));
            Assert.True(init.ConsumeSig(resp.CreateSig()));

            var initLayer = new SptpsRecordLayer();
            var respLayer = new SptpsRecordLayer();
            initLayer.EnableEncryption(init.OutCipherKey, init.InCipherKey);
            respLayer.EnableEncryption(resp.OutCipherKey, resp.InCipherKey);

            byte[] frame = initLayer.EncodeRecord(0, System.Text.Encoding.ASCII.GetBytes("12 edge\n"));
            Assert.Equal(SptpsDecodeResult.Ok, respLayer.TryDecodeRecord(frame, out _, out byte[] got, out _));
            Assert.Equal("12 edge\n", System.Text.Encoding.ASCII.GetString(got));
        }
    }
}
