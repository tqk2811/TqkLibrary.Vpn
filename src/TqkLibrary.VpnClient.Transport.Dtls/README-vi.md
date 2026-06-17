# TqkLibrary.VpnClient.Transport.Dtls

> **Transport DTLS 1.2** — hiện thực [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L9) bằng **DTLS 1.2 client qua BouncyCastle** (`Org.BouncyCastle.Tls.DtlsClientProtocol`). Bọc một datagram pipe UDP "thô" rồi mã hóa/giải mã từng datagram thành một DTLS record. Đây là concrete transport dùng chung cho **đường dữ liệu DTLS của OpenConnect** (V.5c).

## Mục đích

`SslStream` của BCL **chỉ làm TLS, không làm DTLS** trên cả `net8.0` lẫn `netstandard2.0`. Vì vậy handshake + record layer chạy qua **BouncyCastle** (`DtlsClientProtocol`) — package `BouncyCastle.Cryptography` 2.4.0 đã ref ở project `Crypto`, ở đây ref **không điều kiện cho cả 2 TFM**.

Project chỉ phơi **một type công khai** [`DtlsDatagramTransport`](DtlsDatagramTransport.cs#L28): nhận một `IDatagramTransport` bên trong (pipe UDP plaintext), `ConnectAsync` chạy handshake DTLS 1.2 client, sau đó mỗi `SendAsync` = 1 DTLS record mã hóa, mỗi `ReceiveAsync` = 1 DTLS record giải mã (giữ nguyên ranh giới datagram giống UDP — drop-in thay UDP thô). Vì handshake/record layer của BouncyCastle là **đồng bộ (blocking)**, project bắc một cầu sync↔async nội bộ và offload mọi lời gọi blocking ra thread-pool.

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — ngang hàng với `TlsByteStream` (F.1, hiện thực `IByteStreamTransport`); cả hai nằm dưới tầng DRIVER, chỉ phụ thuộc `Abstractions`.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ Abstractions:**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — `IDatagramTransport`.
  - **PackageReference:** `BouncyCastle.Cryptography` 2.4.0 (không điều kiện cả 2 TFM — `Org.BouncyCastle.Tls` cho DTLS).
- **Được dùng bởi (dự kiến):** driver **OpenConnect** (V.5c — đường dữ liệu DTLS song song, fallback TLS). Hiện chưa có consumer trong solution; OpenConnect sẽ wire ở V.5c.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.Dtls/
├── DtlsDatagramTransport.cs                    IDatagramTransport: bọc UDP pipe → handshake DTLS 1.2 client → mã hóa/giải mã từng datagram
├── DefaultDtlsClient.cs                         (internal) TlsClient của BouncyCastle: pin DTLS 1.2 + AEAD suites + wire cert-callback
├── BouncyCastleDatagramBridge.cs                (internal) cầu sync↔async: IDatagramTransport ↔ Org.BouncyCastle.Tls.DatagramTransport
└── DtlsServerCertificateValidationCallback.cs   delegate xác thực/pin cert server (tùy chọn; null = chấp nhận mọi cert)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `DtlsDatagramTransport` | `IDatagramTransport` công khai: ctor nhận inner `IDatagramTransport` + `DtlsServerCertificateValidationCallback?` + `ownsInner`; `ConnectAsync` chạy handshake DTLS 1.2 client (blocking trên thread-pool, hủy bằng cancel→`Close()` bridge); `SendAsync`/`ReceiveAsync` = 1 DTLS record mã hóa/giải mã; phơi `SendLimit`/`ReceiveLimit`; `DisposeAsync` gửi close_notify + đóng bridge (+ inner nếu `ownsInner`) | [DtlsDatagramTransport.cs:28](DtlsDatagramTransport.cs#L28) |
| `DefaultDtlsClient` | (internal) `DefaultTlsClient`: `GetSupportedVersions`=DTLS 1.2; `GetSupportedCipherSuites`=AEAD (ECDHE/DHE-RSA + ECDSA + RSA key-transport, AES-GCM); `GetAuthentication` bắc cert-callback (null⇒accept all; reject⇒`TlsFatalAlert`); client **không** cert (anonymous) | [DefaultDtlsClient.cs:15](DefaultDtlsClient.cs#L15) |
| `BouncyCastleDatagramBridge` | (internal) cầu sync↔async: vòng nền pull datagram từ `IDatagramTransport.ReceiveAsync` vào hàng đợi mà `Receive(buf,off,len,waitMillis)` blocking rút (timeout⇒`-1` cho retransmit timer của DTLS chạy); `Send` chạy `SendAsync` đồng bộ | [BouncyCastleDatagramBridge.cs:19](BouncyCastleDatagramBridge.cs#L19) |
| `DtlsServerCertificateValidationCallback` | delegate `(TlsServerCertificate) → bool` xác thực/pin cert server lúc handshake (analogue của `RemoteCertificateValidationCallback` nhưng nhận cert BouncyCastle) | [DtlsServerCertificateValidationCallback.cs:15](DtlsServerCertificateValidationCallback.cs#L15) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| RFC 6347 (DTLS 1.2) | `DtlsDatagramTransport` + `DefaultDtlsClient` (qua `Org.BouncyCastle.Tls.DtlsClientProtocol`) | [DtlsDatagramTransport.cs:58](DtlsDatagramTransport.cs#L58) · [DefaultDtlsClient.cs:24](DefaultDtlsClient.cs#L24) | Handshake + record layer do BouncyCastle hiện thực; project pin version `ProtocolVersion.DTLSv12.Only()` |
| RFC 5288 / 5289 (AES-GCM cipher suites cho TLS/ECDHE) | `DefaultDtlsClient.GetSupportedCipherSuites` | [DefaultDtlsClient.cs:27](DefaultDtlsClient.cs#L27) | Chỉ chào AEAD: ECDHE/DHE-RSA + ECDSA + RSA key-transport, AES-128/256-GCM |

## API / cách dùng

```csharp
// Bọc một datagram pipe UDP plaintext trong DTLS 1.2; cert mặc định chấp nhận mọi cert.
IDatagramTransport udp = /* UDP socket sau IDatagramTransport, vd UdpDatagramSocket của driver */;
var dtls = new DtlsDatagramTransport(udp,
    certificateValidationCallback: cert => /* pin/validate cert ở đây */ true); // null ⇒ accept all
await dtls.ConnectAsync(cancellationToken);       // chạy handshake DTLS 1.2 client

await dtls.SendAsync(payload);                     // 1 datagram = 1 DTLS record mã hóa
byte[] buf = new byte[dtls.ReceiveLimit];
int n = await dtls.ReceiveAsync(buf);              // 1 DTLS record giải mã
await dtls.DisposeAsync();                          // gửi close_notify + đóng (mặc định đóng cả inner pipe)
```

## Luồng nội bộ

### Handshake (`ConnectAsync` — [DtlsDatagramTransport.cs:58](DtlsDatagramTransport.cs#L58))

1. `inner.ConnectAsync` (bind/resolve UDP) → dựng [`BouncyCastleDatagramBridge`](BouncyCastleDatagramBridge.cs#L19) (khởi động vòng nền pull inbound).
2. Dựng `BcTlsCrypto` + [`DefaultDtlsClient`](DefaultDtlsClient.cs#L15) + `DtlsClientProtocol`.
3. Chạy `protocol.Connect(client, bridge)` **trên thread-pool** (`Task.Run`) — blocking, retransmit timer của DTLS chạy qua `waitMillis` của bridge. Cancel của caller → đăng ký `Close()` bridge để `Receive` blocking trả về → handshake hủy.
4. Cert server: BouncyCastle gọi `NotifyServerCertificate` → cert-callback (null⇒accept; false⇒`TlsFatalAlert(bad_certificate)` hủy handshake).

### Send / Receive (sau handshake)

- `SendAsync`: copy `ReadOnlyMemory` ra `byte[]` → `DtlsTransport.Send` (blocking, offload `Task.Run`) = 1 record mã hóa. **Lưu ý:** DTLS application_data record mang ≥1 byte — BouncyCastle **từ chối** gửi datagram rỗng.
- `ReceiveAsync`: `DtlsTransport.Receive(...,200ms)` trong vòng lặp (offload `Task.Run`); `-1` = timeout (chưa có record) → lặp tiếp để honor cancel mà không busy-spin; có record → copy ra buffer.

### Cầu sync↔async ([BouncyCastleDatagramBridge.cs:19](BouncyCastleDatagramBridge.cs#L19))

- Vòng nền `PumpInboundAsync`: `inner.ReceiveAsync` → `BlockingCollection` (`ConcurrentQueue`). 0-byte không phải EOF (UDP) → bỏ qua, nghe tiếp.
- `Receive(buf,off,len,waitMillis)`: `TryTake(waitMillis)`; rỗng → `-1` (để retransmit timer DTLS chạy).
- `Send`: `inner.SendAsync(...).GetAwaiter().GetResult()` (đồng bộ; chỉ chạy trên thread IO của handshake/loop, không trên đường async công khai).

## Trạng thái & ghi chú

- **Đã hiện thực:** DTLS 1.2 client transport hoàn chỉnh (handshake + round-trip 2 chiều), cert-callback tùy chọn, build xanh cả `netstandard2.0` + `net8.0`. Test **offline** [`DtlsDatagramTransportTests`](../../tests/TqkLibrary.VpnClient.Transport.Dtls.Tests/DtlsDatagramTransportTests.cs) dựng **server DTLS giả lập** bằng BouncyCastle (`DtlsServerProtocol` + cert RSA self-signed) qua loopback datagram pipe in-memory: handshake, round-trip nhiều datagram 2 chiều, cert-callback quan sát đúng cert, reject cert ⇒ abort handshake, **record loss** (drop flight đầu ⇒ DTLS retransmit ⇒ vẫn xong) + **reorder** (đảo 2 datagram đầu server ⇒ vẫn xong).
- **netstandard2.0 vs net8.0:** overload `Receive(Span<byte>,...)` + `Send(ReadOnlySpan<byte>)` của interface `DatagramTransport` **chỉ có trong build net6.0** của BouncyCastle (dùng cho target `net8.0`); build `netstandard2.0` chỉ có overload `byte[]`. `BouncyCastleDatagramBridge` rào 2 overload Span bằng `#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER` cho khớp từng build package.
- **Threading:** `DtlsTransport` của BouncyCastle là đồng bộ; record layer chịu **1 sender + 1 receiver** đồng thời (mô hình "1 write loop + 1 read loop" của driver), **không** an toàn khi gọi `SendAsync` (hoặc `ReceiveAsync`) từ 2 thread cùng lúc — giống socket thô.
- **Hạn chế đã biết / việc sau:**
  - **Chỉ DTLS 1.2** (pin `DTLSv12`); DTLS 1.3 chưa chào (gateway VPN hiện đa số chưa triển khai).
  - **Chưa có consumer thật** trong solution — OpenConnect wire ở **V.5c** (đường dữ liệu DTLS song song + fallback TLS).
  - **Client anonymous** (không cert client) — DTLS ở OpenConnect được CSTP session ủy quyền, không mutual PKI.
  - **Validate live** (ocserv Docker bật DTLS) chờ **Q.1**.

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5/§9 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
