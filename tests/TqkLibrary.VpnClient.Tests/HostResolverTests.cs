using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Net;
using Xunit;

namespace TqkLibrary.VpnClient.Tests
{
    /// <summary>
    /// Offline coverage of the outer-transport host resolver (P1.2). The family-selection core is pure (no DNS); the
    /// async path is exercised only with IP literals so it stays network-free.
    /// </summary>
    public class HostResolverTests
    {
        static readonly IPAddress V4a = IPAddress.Parse("203.0.113.1");
        static readonly IPAddress V4b = IPAddress.Parse("203.0.113.2");
        static readonly IPAddress V6a = IPAddress.Parse("2001:db8::1");
        static readonly IPAddress V6b = IPAddress.Parse("2001:db8::2");

        [Theory]
        [InlineData(AddressFamilyPreference.Auto)]
        [InlineData(AddressFamilyPreference.IPv4)]
        public void DualStack_PrefersFirstIPv4_ForAutoAndIPv4(AddressFamilyPreference preference)
        {
            IPAddress? chosen = DnsHostResolver.Select(new[] { V6a, V4a, V4b }, preference);
            Assert.Equal(V4a, chosen);                                           // first of the preferred family, in order
        }

        [Fact]
        public void DualStack_PrefersFirstIPv6_ForIPv6()
        {
            IPAddress? chosen = DnsHostResolver.Select(new[] { V4a, V6a, V6b }, AddressFamilyPreference.IPv6);
            Assert.Equal(V6a, chosen);
        }

        [Fact]
        public void IPv6Preference_FallsBackToIPv4_WhenNoIPv6()
        {
            IPAddress? chosen = DnsHostResolver.Select(new[] { V4a, V4b }, AddressFamilyPreference.IPv6);
            Assert.Equal(V4a, chosen);                                           // "ưu tiên config, fallback họ còn lại"
        }

        [Fact]
        public void IPv4Preference_FallsBackToIPv6_WhenNoIPv4()
        {
            IPAddress? chosen = DnsHostResolver.Select(new[] { V6a, V6b }, AddressFamilyPreference.IPv4);
            Assert.Equal(V6a, chosen);
        }

        [Fact]
        public void EmptyList_ReturnsNull()
        {
            Assert.Null(DnsHostResolver.Select(System.Array.Empty<IPAddress>(), AddressFamilyPreference.Auto));
        }

        [Theory]
        [InlineData("203.0.113.7", AddressFamily.InterNetwork)]
        [InlineData("2001:db8::7", AddressFamily.InterNetworkV6)]
        public async Task ResolveAsync_IpLiteral_ReturnsVerbatim_NoDns(string literal, AddressFamily expected)
        {
            IPAddress resolved = await DnsHostResolver.Default.ResolveAsync(literal, AddressFamilyPreference.IPv6, TestContext.Current.CancellationToken);
            Assert.Equal(IPAddress.Parse(literal), resolved);                    // a literal wins over the preference
            Assert.Equal(expected, resolved.AddressFamily);
        }

        [Fact]
        public async Task ResolveAsync_EmptyHost_Throws()
        {
            await Assert.ThrowsAsync<System.ArgumentException>(
                () => DnsHostResolver.Default.ResolveAsync("", AddressFamilyPreference.Auto, TestContext.Current.CancellationToken));
        }
    }
}
