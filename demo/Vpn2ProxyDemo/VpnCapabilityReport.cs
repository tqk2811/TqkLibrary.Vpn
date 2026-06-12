using System;
using System.Collections.Generic;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Kết quả panel "VPN này hỗ trợ gì": phần <see cref="Info"/> (thông tin kết nối tĩnh: IP/DNS/MTU/transport/bảo mật/auth)
    /// + danh sách <see cref="Capabilities"/> (mỗi khả năng = 1 <see cref="VpnCapability"/>). <see cref="Print"/> in ra Console.
    /// </summary>
    internal sealed class VpnCapabilityReport
    {
        public VpnCapabilityReport(string protocolName,
            IReadOnlyList<(string Label, string Value)> info,
            IReadOnlyList<VpnCapability> capabilities)
        {
            ProtocolName = protocolName;
            Info = info;
            Capabilities = capabilities;
        }

        /// <summary>Tên giao thức/driver (vd "sstp", "l2tp-ipsec").</summary>
        public string ProtocolName { get; }

        /// <summary>Thông tin kết nối tĩnh (nhãn → giá trị): IP ảo, DNS, MTU, transport, bảo mật, xác thực, cấp địa chỉ.</summary>
        public IReadOnlyList<(string Label, string Value)> Info { get; }

        /// <summary>Các khả năng đã probe/suy luận (IPv4/IPv6/UDP/Listen TCP/Listen UDP/LAN ảo...).</summary>
        public IReadOnlyList<VpnCapability> Capabilities { get; }

        /// <summary>In panel ra Console (cần <c>Console.OutputEncoding = UTF8</c> để hiện ✓/✗ — Program đã đặt).</summary>
        public void Print()
        {
            Console.WriteLine($"── Khả năng VPN ({ProtocolName}) ─────────────────────────────");
            foreach ((string label, string value) in Info)
                Console.WriteLine($"  {label,-14}: {value}");
            Console.WriteLine();
            foreach (VpnCapability cap in Capabilities)
                Console.WriteLine($"  {Glyph(cap.Status)} {cap.Name,-34} {cap.Detail}");
            Console.WriteLine("──────────────────────────────────────────────────────────────");
            Console.WriteLine();
        }

        static string Glyph(CapabilityStatus status) => status switch
        {
            CapabilityStatus.Yes => "[✓]",
            CapabilityStatus.No => "[✗]",
            CapabilityStatus.Likely => "[~]",
            CapabilityStatus.Unlikely => "[~]",
            _ => "[?]",
        };
    }
}
