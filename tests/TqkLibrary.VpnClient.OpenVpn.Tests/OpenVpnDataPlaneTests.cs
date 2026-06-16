using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.e make-before-break data plane: after a soft-reset swap the previous key generation still decrypts
    /// in-flight packets while new packets use the fresh one, dropping the old one stops accepting it, and the
    /// packet-id watermark raises RekeyNeeded.
    /// </summary>
    public class OpenVpnDataPlaneTests
    {
        // A matched client+server data-channel pair for one key generation (distinct per seed/keyId).
        static (OpenVpnDataChannel client, OpenVpnDataChannel server) Generation(byte keyId, byte seed)
        {
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(seed + i); r2[i] = (byte)(seed * 2 + i); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
            var clientKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: true);
            return (new OpenVpnDataChannel(clientKeys, keyId), new OpenVpnDataChannel(serverKeys, keyId));
        }

        [Fact]
        public void Swap_KeepsPreviousInboundDecryptable_ThenDropStopsIt()
        {
            var (c1, s1) = Generation(0, 0x10);
            var (c2, s2) = Generation(1, 0x20);
            var clientPlane = new OpenVpnDataPlane(c1);
            var serverPlane = new OpenVpnDataPlane(s1);

            // An in-flight gen-0 packet from the server, produced before the client swaps.
            byte[] inFlight = serverPlane.Protect(Encoding.ASCII.GetBytes("pre-rekey from server"));

            // Client rekeys (gen-0 → gen-1) before consuming the in-flight packet; it must still decrypt.
            clientPlane.Swap(c2);
            Assert.True(clientPlane.TryUnprotect(inFlight, out byte[] got));
            Assert.Equal("pre-rekey from server", Encoding.ASCII.GetString(got));

            // New gen-1 traffic flows both ways once the server also swaps.
            serverPlane.Swap(s2);
            byte[] post = clientPlane.Protect(Encoding.ASCII.GetBytes("post-rekey from client"));
            Assert.True(serverPlane.TryUnprotect(post, out byte[] got2));
            Assert.Equal("post-rekey from client", Encoding.ASCII.GetString(got2));

            // After dropping the retained generation, a fresh gen-0 packet is no longer accepted.
            clientPlane.DropPreviousInbound();
            byte[] staleGen0 = s1.Protect(Encoding.ASCII.GetBytes("late gen-0"));
            Assert.False(clientPlane.TryUnprotect(staleGen0, out _));
        }

        [Fact]
        public void RekeyNeeded_FiresWhenPacketIdCrossesWatermark()
        {
            var (c1, _) = Generation(0, 0x30);
            var plane = new OpenVpnDataPlane(c1, rekeyAtPacket: 3, rekeyRetryStep: 1000);
            int fired = 0;
            plane.RekeyNeeded += () => fired++;

            plane.Protect(new byte[] { 1 }); // packet-id 1
            plane.Protect(new byte[] { 2 }); // packet-id 2
            Assert.Equal(0, fired);
            plane.Protect(new byte[] { 3 }); // packet-id 3 ⇒ crosses the watermark
            Assert.Equal(1, fired);
            plane.Protect(new byte[] { 4 }); // still within the same step ⇒ no re-fire
            Assert.Equal(1, fired);
        }
    }
}
