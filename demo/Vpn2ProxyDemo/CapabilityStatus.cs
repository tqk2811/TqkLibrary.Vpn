namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Trạng thái một khả năng VPN trong panel "VPN này hỗ trợ gì" (xem <see cref="VpnCapabilityProbe"/>):
    /// xác nhận có/không bằng probe hoặc sự thật thư viện, hoặc chỉ phỏng đoán (heuristic), hoặc chưa rõ.
    /// </summary>
    internal enum CapabilityStatus
    {
        /// <summary>[✓] Xác nhận CÓ (probe nhận được phản hồi / thực tế đã có).</summary>
        Yes,

        /// <summary>[✗] Xác nhận KHÔNG (thực tế chặn / thư viện chưa hiện thực).</summary>
        No,

        /// <summary>[~] Nhiều khả năng CÓ — suy đoán (heuristic), chưa chắc.</summary>
        Likely,

        /// <summary>[~] Nhiều khả năng KHÔNG — suy đoán (heuristic), chưa chắc.</summary>
        Unlikely,

        /// <summary>[?] Không xác định được (probe lỗi/hết giờ, thiếu dữ kiện).</summary>
        Unknown,
    }
}
