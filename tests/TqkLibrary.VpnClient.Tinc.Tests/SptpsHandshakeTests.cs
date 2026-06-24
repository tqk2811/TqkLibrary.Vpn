using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tinc.Sptps;
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
    }
}
