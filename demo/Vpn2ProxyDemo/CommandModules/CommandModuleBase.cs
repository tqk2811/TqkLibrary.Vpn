using System.CommandLine;
using Vpn2ProxyDemo.CommandModules.Enums;
using Vpn2ProxyDemo.CommandModules.Interfaces;
using Vpn2ProxyDemo.CommandModules.Models;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Base chung cho mọi subcommand action của demo VPN. Lo phần dùng chung: option <c>--vpn</c> (URI target), parse
    /// target, in header, connect VPN (giữ vòng đời tunnel tới hết <c>await using</c>), bắt lỗi. Subclass chỉ implement
    /// <see cref="RunAsync"/> — hành động cụ thể trên tunnel đã lên (probe DNS, dựng proxy, ...) và (tùy chọn) override
    /// <see cref="ValidateOptions"/> để fail-fast option riêng trước khi connect.
    /// <para>
    /// Giao thức (SSTP / L2TP) là phần của URI <c>--vpn</c> — KHÔNG phải subcommand. Subcommand tách theo **hành động**;
    /// thêm action mới = thêm một subclass, không sửa base.
    /// </para>
    /// </summary>
    internal abstract class CommandModuleBase : ICommandModule
    {
        Option<string> VpnOption { get; }

        readonly Command _command;
        public Command Command => _command;

        protected CommandModuleBase(string name, string description)
        {
            _command = new Command(name, description);

            VpnOption = new Option<string>("--vpn")
            {
                Description = "VPN target dạng URI scheme://user:pass@host[:port]. scheme = sstp (MS-SSTP/TLS, default port 443) "
                    + "hoặc l2tp (L2TP/IPsec IKEv1 PSK \"vpn\", NAT-T 500/4500 — bỏ qua port). Thiếu user:pass ⇒ mặc định vpn:vpn.",
                DefaultValueFactory = _ => "sstp://vpn:vpn@public-vpn-226.opengw.net",
            };
            _command.Options.Add(VpnOption);

            _command.SetAction(InvokeAsync);
        }

        async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
        {
            string vpnUri = parseResult.GetValue(VpnOption)!;

            if (!VpnTarget.TryParse(vpnUri, out VpnTarget? target, out string? vpnError))
            {
                Console.WriteLine($"  !! {vpnError}");
                return 1;
            }
            // Subclass tự validate option riêng (vd proxy-host/port) — fail-fast TRƯỚC khi connect (tránh connect ~90s rồi mới báo lỗi).
            string? optError = ValidateOptions(parseResult);
            if (optError != null)
            {
                Console.WriteLine($"  !! {optError}");
                return 1;
            }

            // Tag protocol cho log/header ("sstp"/"l2tp").
            string tag = target!.Protocol.ToString().ToLowerInvariant();
            PrintHeader(tag);

            try
            {
                // Connect VPN theo giao thức đã chọn và trả về tunnel (giữ vòng đời kết nối).
                await using VpnTunnel tunnel = await ConnectAsync(target, ct);

                // Panel "VPN này hỗ trợ gì" — probe (UDP/LAN ảo) + suy luận (IPv6/listen-external) ngay sau khi tunnel lên,
                // TRƯỚC hành động (tự bao timeout, nuốt lỗi nên không làm hỏng lệnh).
                await PrintCapabilitiesAsync(tunnel, ct);

                // Hành động cụ thể của subcommand trên tunnel đã lên.
                await RunAsync(tag, tunnel, parseResult, ct);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("  (đã hủy)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  !! {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine();
            }

            Console.WriteLine("Done.");
            return 0;
        }

        /// <summary>Hành động cụ thể của subcommand trên <paramref name="tunnel"/> đã lên. Subclass đọc option riêng từ <paramref name="parseResult"/>.</summary>
        protected abstract Task RunAsync(string tag, VpnTunnel tunnel, ParseResult parseResult, CancellationToken ct);

        /// <summary>
        /// In panel "VPN này hỗ trợ gì" (<see cref="VpnCapabilityProbe"/>): probe được thì gửi gói thật (UDP/LAN ảo),
        /// còn lại suy từ địa chỉ cấp + năng lực driver. Bao một chặn-trên thời gian + nuốt mọi lỗi (trừ hủy của caller)
        /// để panel không bao giờ làm hỏng hành động chính.
        /// </summary>
        static async Task PrintCapabilitiesAsync(VpnTunnel tunnel, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(20)); // chặn trên an toàn (mỗi sub-probe đã tự timeout ngắn)
                VpnCapabilityReport report = await VpnCapabilityProbe.RunAsync(tunnel, cts.Token);
                report.Print();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException)
            {
                Console.WriteLine("  (probe khả năng VPN quá thời gian)");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  (probe khả năng VPN lỗi: {ex.GetType().Name}: {ex.Message})");
                Console.WriteLine();
            }
        }

        /// <summary>Hook validate option riêng của subclass (gọi TRƯỚC khi connect). Trả message lỗi, hoặc <c>null</c> nếu hợp lệ.</summary>
        protected virtual string? ValidateOptions(ParseResult parseResult) => null;

        /// <summary>Dispatch connect theo giao thức đã parse về hàm static tương ứng của <see cref="VpnTunnel"/>.</summary>
        Task<VpnTunnel> ConnectAsync(VpnTarget target, CancellationToken ct)
            => target.Protocol switch
            {
                VpnProtocol.Sstp => VpnTunnel.ConnectSstpAsync(target.Host, target.Port, target.User, target.Pass, ct),
                VpnProtocol.L2tp => VpnTunnel.ConnectL2tpAsync(target.Host, target.User, target.Pass, target.PreSharedKey, ct),
                _ => throw new ArgumentOutOfRangeException(nameof(target), target.Protocol, "Giao thức VPN không hỗ trợ."),
            };

        void PrintHeader(string protocol)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine($" Vpn2ProxyDemo — Protocol: {protocol}");
            Console.WriteLine("============================================================");
            Console.WriteLine();
        }
    }
}
