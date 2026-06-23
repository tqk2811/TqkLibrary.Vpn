# TqkLibrary.VpnClient.Transport.Tls

> **Transport TLS-over-TCP** — hiện thực [`ITlsByteStream`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) (mở rộng `IByteStreamTransport`, phơi thêm `RemoteCertificate`) bằng cách **bọc một [`TcpByteStream`](../TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs#L22)** trong `SslStream` rồi chạy handshake TLS client. Đây là **bản TLS transport DUY NHẤT dùng chung** cho các driver **SSTP / SoftEther / OpenConnect** (roadmap **F.1**).

## Mục đích

Trước F.1, 3 driver TLS (SSTP, SoftEther, OpenConnect) mỗi cái nhúng một bản `SslStream`-over-`TcpClient` gần trùng nhau (cùng cách capture cert, cùng cách rào TFM). F.1 gom về đây: TLS **build trên** [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (TcpByteStream lo resolve + connect TCP + phơi `Stream`; lớp này chỉ phủ `SslStream` lên). `RemoteCertificate` được phơi vì **SSTP crypto binding** ([MS-SSTP] §3.2.4) băm cert server; các giao thức khác bỏ qua. Mặc định chấp nhận **mọi cert** (định danh server do auth/crypto-binding của từng giao thức lo, không qua PKI), trừ khi truyền `RemoteCertificateValidationCallback` để validate (roadmap **P0.6**).

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — trên `Transport.Tcp`, ngang hàng `Transport.Dtls`/`Transport.RawIp`; dưới tầng DRIVER.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):** `Abstractions` (`ITlsByteStream`/`IHostResolver`/`AddressFamilyPreference`) + [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (`TcpByteStream`). **Không package ngoài** — TLS dùng `System.Net.Security.SslStream` của BCL (cả 2 TFM).
- **Được dùng bởi:** [`Drivers.Sstp`](../TqkLibrary.VpnClient.Drivers.Sstp) (`SstpConnection`/`SstpTransport` default), [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) (`SoftEtherTlsTransportFactory`), [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) (`OpenConnectSocketTransportFactory`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.Tls/
└── TlsByteStream.cs    ITlsByteStream: bọc TcpByteStream + SslStream; 2 ctor (resolve host / IPEndPoint sẵn), capture RemoteCertificate, cert-callback (P0.6), Read/Write/Connect/Dispose theo TFM
```
> `ITlsByteStream` **không** ở đây mà ở [Abstractions/Transport/Interfaces](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) (điểm chung đứng sau interface trong Abstractions — SSTP/SoftEther/OpenConnect chỉ phụ thuộc interface).

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `ITlsByteStream` | (Abstractions) `IByteStreamTransport` + `RemoteCertificate` (cert server, null tới khi connect) | [ITlsByteStream.cs:13](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) |
| `TlsByteStream` | Bọc `TcpByteStream` + `SslStream`: ctor `(host, port, cb, afPref, resolver)` / `(host, IPEndPoint, cb)`; callback validate cert (null=accept any) + capture `RemoteCertificate`; `AuthenticateAsClient(TargetHost=host)`; cancel theo TFM (net8 token; ns2.0 cancel-by-dispose) | [TlsByteStream.cs:26](TlsByteStream.cs#L26) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class áp dụng | Ghi chú |
|-------|---------------|---------|
| TLS 1.2/1.3 (`SslStream`) | `TlsByteStream` | Handshake client qua BCL `SslStream.AuthenticateAsClientAsync`; SNI = host gốc (giữ khi connect bằng IPAddress). |
| RFC 6125 (SNI/TargetHost) | `TlsByteStream` | `SslClientAuthenticationOptions.TargetHost = host` (net8); `AuthenticateAsClientAsync(host)` (ns2.0). |

## API / cách dùng

```csharp
// Driver TLS (SSTP/SoftEther/OpenConnect) ráp transport TLS dùng chung:
ITlsByteStream tls = new TlsByteStream("vpn.example", 443,
    certificateValidationCallback: null,                 // null = accept any (định danh qua crypto binding)
    addressFamilyPreference: AddressFamilyPreference.Auto);
await tls.ConnectAsync(ct);
X509Certificate2? serverCert = tls.RemoteCertificate;    // SSTP crypto binding cần cert này

// Khi caller đã resolve sẵn endpoint (vd OpenConnect correlate DTLS):
var tls2 = new TlsByteStream("vpn.example", new IPEndPoint(addr, 443));
await tls2.ConnectAsync(ct);
```

## Luồng nội bộ

### `ConnectAsync` ([TlsByteStream.cs:64](TlsByteStream.cs#L64))
1. `_tcp.ConnectAsync` — `TcpByteStream` resolve (theo `AddressFamilyPreference`) + mở socket + phơi `Stream`.
2. `new SslStream(_tcp.Stream, leaveInnerStreamOpen: false, validationCb)` — callback **capture** cert (`RemoteCertificate = new X509Certificate2(cert)`) rồi uỷ quyết định cho `certificateValidationCallback` (null ⇒ `true`, accept any).
3. `AuthenticateAsClientAsync(TargetHost=host)` (net8 overload token; ns2.0 cancel-by-dispose).

### `Dispose`
- `_ssl.Dispose()` đóng inner `NetworkStream` (`leaveInnerStreamOpen:false`); `_tcp.Dispose()` đóng `TcpClient` (idempotent); `RemoteCertificate?.Dispose()`.

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** `TlsByteStream` hoàn chỉnh (2 ctor, capture cert, cert-callback), build xanh cả `netstandard2.0` + `net8.0`. Test offline [`TlsByteStreamTests`](../../tests/TqkLibrary.VpnClient.Transport.Tls.Tests/TlsByteStreamTests.cs): round-trip TLS qua loopback `TcpListener` + server `SslStream` cert tự ký runtime, `RemoteCertificate` được capture, callback từ chối ⇒ handshake ném, `ReadAsync` throw khi chưa connect.
- **netstandard2.0 vs net8.0:** ns2.0 không có `SslStream.AuthenticateAsClientAsync(options, token)`/`ReadAsync(Memory,token)` ⇒ cancel-by-dispose + overload mảng (`MemoryMarshal`); guard `#if NET5_0_OR_GREATER`. **DTLS không dùng `SslStream`** (BCL không hỗ trợ) — đường DTLS của OpenConnect ở [`Transport.Dtls`](../TqkLibrary.VpnClient.Transport.Dtls) qua BouncyCastle.
- **Ghi chú:** lớp này thay 3 bản TLS-over-TCP nhúng-trong-driver cũ (SSTP `TlsByteStream`, SoftEther `SoftEtherTlsTransport`, OpenConnect inlined) — F.1 đã gom. OpenVPN-TCP **không** dùng lớp này (TLS in-band, chỉ cần [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) trần).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (F.1).
