# 01 — Ràng buộc nền tảng: KHÔNG bước cài đặt; được xin quyền lúc chạy

> **[As-built]** Ràng buộc thật là **no-install**, không phải no-admin: admin/raw-socket nay là **tùy chọn hạng nhất**
> khi consumer cần proto tùy ý (PPTP GRE proto-47 V.6; native ESP proto-50 P0.8c) qua `Transport.RawIp` (F.9, chưa build,
> cần elevate). SSTP/L2TP/IKEv2/OpenVPN/WireGuard/SoftEther/OpenConnect vẫn no-admin. Chi tiết: [`10`](10-codebase-architecture-and-flow.md)
> §"Khác biệt". File này (mô tả "đường mặc định KHÔNG cần quyền") vẫn khớp các driver đó.

## Lằn ranh cứng DUY NHẤT = không có bước cài đặt/setup

- KHÔNG TUN/TAP adapter, KHÔNG kernel driver (Npcap/Wintun/WinTap), KHÔNG cài service.
- App **chạy thẳng** (xcopy-run).
- → đây là lý do **bắt buộc tự xây userspace TCP/IP stack** (không mượn adapter ảo của OS).

## Được phép: xin đặc quyền lúc chạy (UAC/sudo)

- Raw socket, bind cổng thấp... đều OK **khi có quyền** — vì đó là *quyền chạy*, không phải *cài đặt*.
- Tinh thần: "chạy lên, cần thì xin quyền".

| Quy tắc | Hệ quả |
|---|---|
| ❌ KHÔNG cài TUN/TAP / driver / service | userspace TCP/IP stack tự làm, không bao giờ dùng adapter ảo OS |
| ✅ Được elevate (admin/root) | raw socket hợp lệ; giao thức raw-IP (ESP/50, GRE/47, EtherIP/97, L2TPv3/115, PPTP) khả thi khi elevated |
| Ưu tiên đường KHÔNG cần quyền khi có thể | L2TP/IPsec mặc định NAT-T/4500 (không cần admin); SSTP chỉ TLS/443 |

## Vì sao raw socket = đặc quyền (không phải cài đặt)

- Với `TcpClient`/`UdpClient` thường, **OS tự ghi header IP + TCP/UDP**; ta chỉ kiểm soát payload, không kiểm soát trường "IP protocol" (luôn 6/TCP hoặc 17/UDP).
- Giao thức như GRE cần `IP protocol = 47` → bắt buộc **raw socket (`SOCK_RAW`)** để tự ghi IP header.
- Raw socket cần: Linux `root`/`CAP_NET_RAW`; Windows nhóm `Administrators` (kiểm tra ngay lúc tạo socket từ Win2000/Vista; user thường → `WSAEACCES`).
- Đây là **quyền**, không phải **cài đặt** → nằm trong ranh giới cho phép.

## `Transport.RawIp` — first-class, cần elevate

- **Tự phát hiện quyền** lúc khởi tạo: thử mở `new Socket(AddressFamily.InterNetwork, SocketType.Raw, (ProtocolType)47)` / kiểm token elevation.
- Driver dùng nó khai báo `RequiresElevation = true` (+ `RequiresRawIpSocket`).
- Façade: đủ quyền → chạy; thiếu → **báo rõ** (`VpnElevationRequiredException`) để app host **tự relaunch elevated**. Lib KHÔNG tự bật UAC giữa tiến trình.

### Độ tin cậy theo nền tảng (đã verify)
| Nền tảng | Gửi GRE/47 | Nhận GRE/47 | Ghi chú |
|---|---|---|---|
| Linux (root/CAP_NET_RAW) | ✅ ổn | ✅ ổn | giống `pptp-linux`; .NET `SocketType.Raw` hỗ trợ |
| Windows (Administrator) | ✅ qua `IP_HDRINCL` | ⚠️ **bấp bênh** | OS siết raw receive, có thể chặn proto-47; PPTP gốc Windows dùng kernel driver `raspptp.sys` |

→ Driver raw-IP gắn nhãn **"reliable: Linux; best-effort: Windows"**.

## Hệ quả cho L2TP/IPsec (đường mặc định KHÔNG cần quyền)

- ESP không đi raw proto-50 ở core → **bắt buộc ESP-in-UDP/4500 (NAT-T, RFC 3948)**.
- IKE+ESP chạy trên UDP socket **cổng nguồn ephemeral** (KHÔNG bind 500/4500 — tránh đụng dịch vụ **IKEEXT** của Windows đang giữ 2 cổng đó); gửi tới `server:500` → float `server:4500`; **ép NAT-T** (client tự xưng "sau NAT").
- **Rủi ro #1:** vài server từ chối forced-NAT-T khi không thực sự có NAT, hoặc đòi src-port=500 → fallback **native ESP (proto-50 raw, cần elevate)**. Test theo từng server (strongSwan/RRAS/SoftEther).

> **[As-built]** Đã làm phần userspace của rủi ro #1: (a) phân loại lỗi reject (`IkeV1Client.TryReadRejectNotify`) +
> (b) honest-first NAT-T opt-in (`L2tpIpsecNatTraversalMode.HonestFirst` — bind cổng 500 thật + NAT-D trung thực +
> `IkeV1Client.DetectNat`, không-NAT ⇒ fallback forced). **Chưa làm**: (c) native ESP proto-50 — cần `Transport.RawIp`
> (F.9, admin) + lab Docker (Q.1). Roadmap [`11`](11-todo-roadmap.md) §P0.8; trạng thái [`10`](10-codebase-architecture-and-flow.md) §6/§9.

## Nguồn
- MS — TCP/IP raw sockets: https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2
- Linux raw(7): https://man7.org/linux/man-pages/man7/raw.7.html
- .NET SocketType: https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.sockettype
- RFC 3948 (UDP Encapsulation of ESP): https://datatracker.ietf.org/doc/html/rfc3948
