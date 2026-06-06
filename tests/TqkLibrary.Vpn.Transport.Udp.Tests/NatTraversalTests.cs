using TqkLibrary.Vpn.Transport.Udp;
using Xunit;

namespace TqkLibrary.Vpn.Transport.Udp.Tests
{
    public class NatTraversalTests
    {
        [Fact]
        public void WrapIke_PrependsZeroMarker()
        {
            byte[] ike = { 1, 2, 3, 4, 5 };
            byte[] framed = NatTraversal.WrapIke(ike);

            Assert.Equal(NatTraversal.MarkerLength + ike.Length, framed.Length);
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, framed[..4]);
            Assert.Equal(ike, framed[4..]);
        }

        [Fact]
        public void Classify_ZeroMarker_IsIke()
        {
            byte[] datagram = NatTraversal.WrapIke(new byte[] { 0x29, 0x00, 0x00, 0x08 });
            Assert.Equal(NatTPacketKind.Ike, NatTraversal.Classify(datagram));
            Assert.Equal(new byte[] { 0x29, 0x00, 0x00, 0x08 }, NatTraversal.UnwrapIke(datagram));
        }

        [Fact]
        public void Classify_NonZeroSpi_IsEsp()
        {
            byte[] esp = { 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x01 }; // SPI + seq
            Assert.Equal(NatTPacketKind.Esp, NatTraversal.Classify(esp));
        }

        [Fact]
        public void Classify_BareMarker_IsInvalid()
        {
            Assert.Equal(NatTPacketKind.Invalid, NatTraversal.Classify(new byte[] { 0, 0, 0, 0 }));
            Assert.Equal(NatTPacketKind.Invalid, NatTraversal.Classify(new byte[] { 0, 0 }));
        }
    }
}
