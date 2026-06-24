using System.Text;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Nebula.Handshake;
using Xunit;

namespace TqkLibrary.VpnClient.Nebula.Tests
{
    public class NebulaNoiseIxHandshakeTests
    {
        static byte[] NewStatic()
        {
            var dh = new Curve25519DhGroup();
            return dh.GeneratePrivateKey();
        }

        [Fact]
        public void IxHandshake_SelfPair_AgreesOnCrossedTransportKeys()
        {
            byte[] initStatic = NewStatic();
            byte[] respStatic = NewStatic();

            var initiator = new NebulaNoiseIxHandshake(initStatic);
            var responder = new NebulaNoiseIxHandshake(respStatic);

            byte[] payload1 = Encoding.ASCII.GetBytes("initiator handshake payload");
            byte[] payload2 = Encoding.ASCII.GetBytes("responder handshake payload");

            // msg1: initiator -> responder
            byte[] msg1 = initiator.CreateInitiation(payload1);
            Assert.True(responder.ConsumeInitiation(msg1, out byte[] recoveredP1));
            Assert.Equal(payload1, recoveredP1);

            // The responder learns the initiator's static public key (Noise s token).
            Assert.Equal(new Curve25519DhGroup().DerivePublicValue(initStatic), responder.RemoteStaticPublic);

            // msg2: responder -> initiator
            byte[] msg2 = responder.CreateResponse(payload2);
            Assert.True(initiator.ConsumeResponse(msg2, out byte[] recoveredP2));
            Assert.Equal(payload2, recoveredP2);

            // The initiator learns the responder's static public key.
            Assert.Equal(new Curve25519DhGroup().DerivePublicValue(respStatic), initiator.RemoteStaticPublic);

            // Transport keys are crossed: initiator.send == responder.recv and vice versa.
            (byte[] iSend, byte[] iRecv) = initiator.Split();
            (byte[] rSend, byte[] rRecv) = responder.Split();
            Assert.Equal(iSend, rRecv);
            Assert.Equal(iRecv, rSend);
            Assert.NotEqual(iSend, iRecv);
        }

        [Fact]
        public void IxHandshake_Msg1_StaticAndPayloadArePlaintext()
        {
            // In IX msg1 nothing is encrypted yet: msg = e.pub(32) || s.pub(32) || payload (no AEAD tags).
            byte[] initStatic = NewStatic();
            var initiator = new NebulaNoiseIxHandshake(initStatic);
            byte[] payload = Encoding.ASCII.GetBytes("hello");
            byte[] msg1 = initiator.CreateInitiation(payload);

            Assert.Equal(32 + 32 + payload.Length, msg1.Length);
            byte[] sPub = new Curve25519DhGroup().DerivePublicValue(initStatic);
            Assert.Equal(sPub, msg1[32..64]);          // static pubkey is in the clear
            Assert.Equal(payload, msg1[64..]);          // payload is in the clear
        }

        [Fact]
        public void IxHandshake_Msg2_StaticAndPayloadAreEncrypted()
        {
            byte[] initStatic = NewStatic();
            byte[] respStatic = NewStatic();
            var initiator = new NebulaNoiseIxHandshake(initStatic);
            var responder = new NebulaNoiseIxHandshake(respStatic);

            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            Assert.True(responder.ConsumeInitiation(msg1, out _));
            byte[] payload2 = Encoding.ASCII.GetBytes("secret");
            byte[] msg2 = responder.CreateResponse(payload2);

            // e.pub(32) + enc(s.pub)+tag(32+16) + enc(payload)+tag(len+16)
            Assert.Equal(32 + (32 + 16) + (payload2.Length + 16), msg2.Length);
            byte[] respPub = new Curve25519DhGroup().DerivePublicValue(respStatic);
            Assert.NotEqual(respPub, msg2[32..64]); // responder static is NOT in the clear (encrypted)
        }

        [Fact]
        public void IxHandshake_TamperedMsg2_FailsConsume()
        {
            var initiator = new NebulaNoiseIxHandshake(NewStatic());
            var responder = new NebulaNoiseIxHandshake(NewStatic());
            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            responder.ConsumeInitiation(msg1, out _);
            byte[] msg2 = responder.CreateResponse(Array.Empty<byte>());

            byte[] tampered = (byte[])msg2.Clone();
            tampered[^1] ^= 0xFF;
            Assert.False(initiator.ConsumeResponse(tampered, out _));
        }

        [Fact]
        public void IxHandshake_ChaChaPolyVariant_AlsoInteroperates()
        {
            // A chachapoly Nebula network: same handshake logic, different AEAD + protocol-name cipher segment.
            const string name = "Noise_IX_25519_ChaChaPoly_SHA256";
            var initiator = new NebulaNoiseIxHandshake(NewStatic(), cipher: new ChaCha20Poly1305Cipher(), protocolName: name);
            var responder = new NebulaNoiseIxHandshake(NewStatic(), cipher: new ChaCha20Poly1305Cipher(), protocolName: name);

            byte[] msg1 = initiator.CreateInitiation(Encoding.ASCII.GetBytes("p1"));
            Assert.True(responder.ConsumeInitiation(msg1, out _));
            byte[] msg2 = responder.CreateResponse(Encoding.ASCII.GetBytes("p2"));
            Assert.True(initiator.ConsumeResponse(msg2, out _));

            (byte[] iSend, byte[] iRecv) = initiator.Split();
            (byte[] rSend, byte[] rRecv) = responder.Split();
            Assert.Equal(iSend, rRecv);
            Assert.Equal(iRecv, rSend);
        }
    }
}
