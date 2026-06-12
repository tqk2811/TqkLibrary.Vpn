using Vpn2ProxyDemo.CommandModules.Enums;

namespace Vpn2ProxyDemo.CommandModules.Models
{
    /// <summary>
    /// Tham số kết nối VPN parse từ option <c>--vpn</c> dạng URI <c>scheme://user:pass@host[:port][?psk=...]</c>.
    /// <para>
    /// <c>scheme</c> → <see cref="VpnProtocol"/> (<c>sstp</c>/<c>l2tp</c>), <c>user:pass</c> → credential (thiếu thì mặc
    /// định <c>vpn:vpn</c> kiểu VPN Gate), <c>host</c> → địa chỉ gateway, <c>port</c> → cổng (chỉ SSTP dùng, default
    /// 443; L2TP/IPsec cố định NAT-T 500/4500 nên bỏ qua port), <c>?psk=</c> → pre-shared key (chỉ L2TP/IPsec dùng,
    /// thiếu thì mặc định <c>vpn</c> kiểu VPN Gate).
    /// </para>
    /// </summary>
    internal sealed class VpnTarget
    {
        public VpnTarget(VpnProtocol protocol, string host, int port, string user, string pass, string preSharedKey = "vpn")
        {
            Protocol = protocol;
            Host = host;
            Port = port;
            User = user;
            Pass = pass;
            PreSharedKey = preSharedKey;
        }

        public VpnProtocol Protocol { get; }
        public string Host { get; }

        /// <summary>Cổng gateway. Với SSTP đã áp default 443 nếu URI không ghi; L2TP bỏ qua giá trị này.</summary>
        public int Port { get; }
        public string User { get; }
        public string Pass { get; }

        /// <summary>Pre-shared key IKEv1 (group PSK). Chỉ L2TP/IPsec dùng; thiếu <c>?psk=</c> ⇒ mặc định <c>vpn</c> (VPN Gate).</summary>
        public string PreSharedKey { get; }

        /// <summary>
        /// Parse URI <c>scheme://user:pass@host[:port][?psk=...]</c>. Trả <c>false</c> + <paramref name="error"/> mô tả nếu URI
        /// không hợp lệ, scheme không phải <c>sstp</c>/<c>l2tp</c>, hoặc thiếu host. Thiếu <c>user:pass</c> ⇒ mặc định
        /// <c>vpn:vpn</c>; SSTP thiếu port ⇒ 443; L2TP thiếu <c>?psk=</c> ⇒ mặc định <c>vpn</c>.
        /// </summary>
        public static bool TryParse(string value, out VpnTarget? target, out string? error)
        {
            target = null;
            error = null;

            if (string.IsNullOrWhiteSpace(value))
            {
                error = "--vpn trống. Cần dạng scheme://user:pass@host[:port] (vd sstp://vpn:vpn@public-vpn-226.opengw.net).";
                return false;
            }
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                error = $"--vpn '{value}' không phải URI hợp lệ. Cần dạng scheme://user:pass@host[:port].";
                return false;
            }
            if (!Enum.TryParse(uri.Scheme, ignoreCase: true, out VpnProtocol protocol))
            {
                error = $"--vpn scheme '{uri.Scheme}' không hỗ trợ. Chỉ 'sstp' (MS-SSTP) hoặc 'l2tp' (L2TP/IPsec).";
                return false;
            }
            if (string.IsNullOrEmpty(uri.Host))
            {
                error = $"--vpn '{value}' thiếu host.";
                return false;
            }

            // user:pass (percent-decoded). Thiếu ⇒ vpn:vpn (mặc định VPN Gate).
            string user = "vpn";
            string pass = "vpn";
            string userInfo = uri.UserInfo;
            if (!string.IsNullOrEmpty(userInfo))
            {
                int sep = userInfo.IndexOf(':');
                if (sep < 0)
                {
                    user = Uri.UnescapeDataString(userInfo);
                }
                else
                {
                    user = Uri.UnescapeDataString(userInfo.Substring(0, sep));
                    pass = Uri.UnescapeDataString(userInfo.Substring(sep + 1)); // password được phép chứa ':'
                }
                if (string.IsNullOrEmpty(user)) user = "vpn";
            }

            int port = uri.Port; // -1 nếu URI không ghi port
            if (protocol == VpnProtocol.Sstp && port < 0) port = 443;

            // PSK từ query ?psk=... (percent-decoded). Thiếu ⇒ để ctor áp default "vpn" (VPN Gate, chỉ L2TP dùng).
            string? psk = TryGetQueryValue(uri.Query, "psk");
            target = string.IsNullOrEmpty(psk)
                ? new VpnTarget(protocol, uri.Host, port, user, pass)
                : new VpnTarget(protocol, uri.Host, port, user, pass, psk!);
            return true;
        }

        /// <summary>Lấy giá trị (percent-decoded) của 1 key trong query string <c>?a=1&amp;b=2</c>; không có ⇒ <c>null</c>. Pure helper.</summary>
        static string? TryGetQueryValue(string query, string key)
        {
            if (string.IsNullOrEmpty(query)) return null;
            foreach (string pair in query.TrimStart('?').Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                string k = eq < 0 ? pair : pair.Substring(0, eq);
                if (string.Equals(Uri.UnescapeDataString(k), key, StringComparison.OrdinalIgnoreCase))
                    return eq < 0 ? string.Empty : Uri.UnescapeDataString(pair.Substring(eq + 1));
            }
            return null;
        }
    }
}
