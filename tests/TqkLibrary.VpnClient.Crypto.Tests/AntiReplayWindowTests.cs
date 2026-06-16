using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class AntiReplayWindowTests
    {
        [Fact]
        public void SequenceZero_IsAlwaysRejected()
        {
            var w = new AntiReplayWindow();
            Assert.False(w.Check(0));
        }

        [Fact]
        public void FreshSequences_AdvanceTheWindow()
        {
            var w = new AntiReplayWindow();
            for (uint s = 1; s <= 200; s++)
            {
                Assert.True(w.Check(s));
                w.Commit(s);
            }
            Assert.Equal(200u, w.Highest);
        }

        [Fact]
        public void SeenSequence_IsRejected()
        {
            var w = new AntiReplayWindow();
            w.Commit(10);
            Assert.False(w.Check(10));
        }

        [Fact]
        public void WithinWindow_UnseenSequence_IsAccepted()
        {
            var w = new AntiReplayWindow();
            w.Commit(100);
            Assert.True(w.Check(80)); // 20 behind, within the 64 window? no — 20 < 64, accepted
            w.Commit(80);
            Assert.False(w.Check(80)); // now seen
        }

        [Fact]
        public void OlderThanWindow_IsRejected()
        {
            var w = new AntiReplayWindow();
            w.Commit(100);
            Assert.False(w.Check(100 - 64)); // exactly at the edge → too old
            Assert.False(w.Check(1));        // far behind → too old
        }

        [Fact]
        public void LargeJumpForward_ResetsBitmap_StillRejectsOld()
        {
            var w = new AntiReplayWindow();
            w.Commit(10);
            Assert.True(w.Check(1000));
            w.Commit(1000); // jump > window → bitmap cleared except the new highest
            Assert.False(w.Check(10));   // long behind now
            Assert.True(w.Check(999));   // 1 behind, unseen
        }
    }
}
