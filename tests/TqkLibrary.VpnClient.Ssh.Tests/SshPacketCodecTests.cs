using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Ssh.Cipher;
using TqkLibrary.VpnClient.Ssh.Wire;
using Xunit;

namespace TqkLibrary.VpnClient.Ssh.Tests
{
    /// <summary>
    /// Round-trip tests for the SSH binary packet codec over a loopback byte stream: a payload framed by one codec is
    /// recovered byte-for-byte by a peer codec, in cleartext mode (pre-NEWKEYS) and with the chacha20-poly1305@openssh.com
    /// cipher installed. The sequence numbers advance together, so several packets in a row each open correctly.
    /// </summary>
    public class SshPacketCodecTests
    {
        static byte[] Payload(int n)
        {
            byte[] p = new byte[n];
            for (int i = 0; i < n; i++) p[i] = (byte)(i + 1);
            return p;
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(100)]
        [InlineData(4096)]
        public async Task Cleartext_RoundTrips(int payloadLen)
        {
            var (a, b) = LoopbackByteStream.CreatePair();
            var sender = new SshPacketCodec(a);
            var receiver = new SshPacketCodec(b);
            byte[] payload = Payload(payloadLen);

            await sender.WritePacketAsync(payload, CancellationToken.None);
            byte[] received = await receiver.ReadPacketAsync(CancellationToken.None);
            Assert.Equal(payload, received);
        }

        [Fact]
        public async Task ChaCha20Poly1305_MultiplePackets_RoundTrip()
        {
            var (a, b) = LoopbackByteStream.CreatePair();
            var sender = new SshPacketCodec(a);
            var receiver = new SshPacketCodec(b);

            byte[] keyMaterial = new byte[64];
            for (int i = 0; i < 64; i++) keyMaterial[i] = (byte)(i + 1);
            sender.SetOutboundCipher(new ChaCha20Poly1305OpenSshCipher(keyMaterial));
            receiver.SetInboundCipher(new ChaCha20Poly1305OpenSshCipher(keyMaterial));

            for (int round = 0; round < 5; round++)
            {
                byte[] payload = Payload(10 + round * 37);
                await sender.WritePacketAsync(payload, CancellationToken.None);
                byte[] received = await receiver.ReadPacketAsync(CancellationToken.None);
                Assert.Equal(payload, received);
            }
        }

        [Fact]
        public async Task AesGcm_MultiplePackets_RoundTrip()
        {
            var (a, b) = LoopbackByteStream.CreatePair();
            var sender = new SshPacketCodec(a);
            var receiver = new SshPacketCodec(b);

            byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)(i + 3);
            byte[] iv = new byte[12]; for (int i = 0; i < 12; i++) iv[i] = (byte)(i + 1);
            sender.SetOutboundCipher(new AesGcmOpenSshCipher(key, iv));
            receiver.SetInboundCipher(new AesGcmOpenSshCipher(key, iv));

            for (int round = 0; round < 5; round++)
            {
                byte[] payload = Payload(20 + round * 51);
                await sender.WritePacketAsync(payload, CancellationToken.None);
                byte[] received = await receiver.ReadPacketAsync(CancellationToken.None);
                Assert.Equal(payload, received);
            }
        }
    }
}
