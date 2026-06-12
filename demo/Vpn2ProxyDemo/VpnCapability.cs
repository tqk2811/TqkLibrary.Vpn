namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Một dòng khả năng trong panel "VPN này hỗ trợ gì": tên khả năng + <see cref="CapabilityStatus"/> + lý do/chi tiết
    /// (vì sao có/không, hoặc nguồn suy luận). Probe được thì <see cref="Detail"/> kèm số đo (RTT/ms); chưa probe được
    /// thì kèm lý do tĩnh (NAT / thư viện chưa hỗ trợ).
    /// </summary>
    internal readonly struct VpnCapability
    {
        public VpnCapability(string name, CapabilityStatus status, string detail)
        {
            Name = name;
            Status = status;
            Detail = detail;
        }

        /// <summary>Tên khả năng (vd "UDP", "Listen TCP (mở port ra internet)", "LAN ảo trong VPN").</summary>
        public string Name { get; }

        /// <summary>Trạng thái (có/không/phỏng đoán/chưa rõ).</summary>
        public CapabilityStatus Status { get; }

        /// <summary>Lý do/chi tiết hiển thị kèm trạng thái.</summary>
        public string Detail { get; }
    }
}
