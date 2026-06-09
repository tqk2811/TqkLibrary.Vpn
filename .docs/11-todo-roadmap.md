# 11 — Roadmap & TODO (còn thiếu gì)

> Tổng hợp **việc chưa làm**, đối chiếu plan gốc (`wild-stargazing-spark.md`) + tài liệu as-built
> [`10-codebase-architecture-and-flow.md`](10-codebase-architecture-and-flow.md). Cập nhật khi hoàn thành.
> Ưu tiên: **P1** = nên làm sớm cho 2 driver đang chạy thật · **P2** = chất lượng/độ phủ · **P3** = mở rộng tương lai.

## ✅ Đã xong (baseline)
- Driver **SSTP** live (TLS + PPP/MS-CHAPv2 + crypto binding) và **L2TP/IPsec** live (IKEv1 PSK + ESP + L2TP + PPP).
- **Tách project driver**: `TqkLibrary.Vpn.Drivers` cũ đã chia thành 2 project anh em **`TqkLibrary.Vpn.Drivers.L2tpIpsec`** + **`TqkLibrary.Vpn.Drivers.Sstp`** (file phẳng ở gốc project, giữ `Enums/`+`Models/`); namespace giữ nguyên. SSTP nay **chỉ ref Abstractions + Ppp** (không còn kéo Ipsec/L2tp/Transport.Udp).
- **IKEv2** (`Ipsec/Ike/V2/`) đầy đủ + test, **chưa wire vào driver**.
- Socket API trong tunnel: **TCP** (`VpnTcpClient` → HttpClient) + **UDP** (`VpnUdpClient` → DNS-over-tunnel), đều live.
- NAT-T (forced 500→4500), userspace IPv4/TCP/UDP, anti-replay ESP.
- **Robustness L2TP/IPsec**: keepalive (HELLO + DPD), Phase 2 rekey in-place (make-before-break), teardown sạch (CDN/StopCCN/DELETE) + `DisconnectAsync`/`IAsyncDisposable`, **auto-reconnect** (backoff, stable channel) + event `StateChanged`.
- **Robustness SSTP** (mirror L2TP/IPsec): active keepalive (Echo-Request 30s, chết sau 3 lần thiếu Echo-Response), teardown sạch (Call-Disconnect) + `IAsyncDisposable`, **auto-reconnect** (backoff, stable channel) + event `StateChanged`/`Reconnected`. **Không** rekey (TLS sống dài).
- **Typed exception** `VpnConnectionException` + 3 lớp con (auth/server-reject/network-timeout) wire ở cả 2 driver.
- 11 project `src/` + 11 project `tests/`, build xanh `netstandard2.0`+`net8.0`, **121 test offline pass** (`net8.0`) — gồm IKEv1 capstone, TCP loopback, fuzz parser, L2TP control-channel retransmit-cap; thêm ~12 live integration `[Trait("Category","Integration")]` (chạy offline bằng `--filter "Category!=Integration"`).
- **Demo tích hợp proxy** `demo/Vpn2ProxyDemo`: adapter `IProxySource` (inline trong demo) cho `TqkLibrary.Proxy` 1.0.35 → HTTP/SOCKS proxy local định tuyến qua tunnel; MS-SSTP + L2TP/IPsec → `checkip`.

---

## P1 — Hoàn thiện 2 driver đang dùng (robustness)

- [x] **Keepalive L2TP/IPsec**: **L2TP HELLO** (60s) + **IKE DPD** R-U-THERE/ACK (RFC 3706, 20s, chết sau 3 lần không ACK), trả ACK cho probe của server. → [IkeV1Dpd.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Dpd.cs), [IkeV1Client.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs) (`BuildDpdRUThere`/`BuildDpdAck`/`ProcessInformational`), [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs) (`SendHelloAsync`), điều phối + timers ở [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecConnection.cs).
  - [x] **SSTP keepalive chủ động + phát hiện peer-dead**: gửi **SSTP Echo-Request mỗi 30s**, coi peer chết sau **3 lần liên tiếp** thiếu Echo-Response (reset khi có bất kỳ control inbound); vẫn trả lời Echo-Request của server. Phát hiện rớt từ 3 nguồn: vòng đọc kết thúc (chính), thiếu echo, inbound Call-Disconnect/Call-Abort. → [SstpConnection.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpConnection.cs) (`StartKeepalive`/`SendEchoTickAsync`/`OnControlReceived`/`OnReadLoopEnded`).
- [x] **Rekey theo SA lifetime — Phase 2**: Quick Mode rekey in-place ở ~90% lifetime (3600s), swap `EspSession` make-before-break (giữ SA cũ 10s cho inbound). → [IkeV1Client.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs) (`BuildRekeyQuickMode1/2/3`), [IpsecL2tpTransport.cs](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/IpsecL2tpTransport.cs) (`SwapSession`/`DropPreviousInbound`), [IkeV1Lifetimes.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Lifetimes.cs).
  - [x] **Rekey Phase 1** (28800s) **by-reconnect**: timer hết hạn ở ~90% → `OnLinkLost` → supervisor reconnect (re-Main-Mode toàn bộ). Chưa rekey Phase 1 in-place (chấp nhận gián đoạn ngắn mỗi 8h cho v1).
  - [ ] **Rekey theo sequence-exhaustion**: chưa có — [`EspSession.Protect` @ :34](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L34) dùng `checked(_sequence+1)` nên gói thứ 2³² ném `OverflowException` thay vì rekey; hiện chỉ rekey theo thời gian.
- [x] **Teardown sạch khi disconnect (L2TP/IPsec)**: `DisconnectAsync`/`IAsyncDisposable` gửi `CDN`+`StopCCN` (L2TP) + `DELETE` ESP+ISAKMP (IKE) rồi mới đóng socket (best-effort, timeout 2s). → [IkeV1Delete.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Delete.cs), [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs) (`SendCallDisconnectAsync`/`SendStopControlConnectionAsync`), [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecConnection.cs).
  - [x] **SSTP disconnect sạch**: `DisconnectAsync`/`IAsyncDisposable` gửi **SSTP Call-Disconnect** (best-effort, timeout 2s) rồi mới đóng transport; `SstpVpnConnection.DisposeAsync` await teardown async. → [SstpConnection.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpConnection.cs) (`DisconnectAsync`/`SendTeardownAsync`).
- [x] **Reconnect tự động** khi rớt (exponential backoff 1s→30s ×2 ±20%, vô hạn tới `DisconnectAsync`; bật mặc định, cấu hình qua [L2tpIpsecReconnectOptions](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecReconnectOptions.cs)). Tunnel mới chui sau [SwappablePacketChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs) ổn định → flow trong tunnel sống sót khi same-IP; đổi IP → `session.Reconfigured`. Event `StateChanged` (Connecting/Connected/Reconnecting/Disconnected). → [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecConnection.cs) (`EstablishAsync`/`ReconnectLoopAsync`, lock chống double-supervisor + drop-window race).
  - [x] **Reconnect cho SSTP**: cùng mô hình supervisor + [SwappablePacketChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs) ổn định, backoff cấu hình qua [SstpReconnectOptions](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpReconnectOptions.cs) (bật mặc định); event `StateChanged` (enum `SstpConnectionState`) + `Reconnected`; double-guard `_attemptId` + cancel vòng đọc chống vòng đọc cũ báo rớt giả. → [SstpConnection.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpConnection.cs) (`EstablishAsync`/`ReconnectLoopAsync`/`OnLinkLost`), wiring `Reconnected`→`ApplyReconnect` ở [SstpDriver.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpDriver.cs)/[SstpVpnSession.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpVpnSession.cs); overload [`UseSstp(SstpReconnectOptions)`](../src/TqkLibrary.Vpn/VpnClientBuilder.cs).
- [x] **Phân loại lỗi & timeout rõ ràng** — typed exception + timeout cấu hình + retransmit cap **đã xong**:
  - [x] **Custom exception types**: [VpnConnectionException](../src/TqkLibrary.Vpn.Abstractions/Drivers/VpnConnectionException.cs) (base) + 3 lớp con sealed — [VpnAuthenticationException](../src/TqkLibrary.Vpn.Abstractions/Drivers/VpnAuthenticationException.cs) / [VpnServerRejectedException](../src/TqkLibrary.Vpn.Abstractions/Drivers/VpnServerRejectedException.cs) / [VpnNetworkTimeoutException](../src/TqkLibrary.Vpn.Abstractions/Drivers/VpnNetworkTimeoutException.cs). Wire throw site ở cả 2 driver (SSTP: Nak/non-200/crypto-binding→reject, auth fail→auth, socket/TLS/IO→timeout; L2TP: PSK/HASH_R→auth, no-SA→reject, IKE/rekey no-response→timeout). Caller `OperationCanceledException` **không** bị tái phân loại.
  - [x] **Timeout cấu hình được** — [L2tpIpsecTimeoutOptions](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecTimeoutOptions.cs) đưa **IKE retransmit** (số lần `IkeMaxAttempts` + khoảng `IkeRetransmitInterval`, mặc định 5×2.5s — thay hard-code ở `ExchangeIkeAsync`/`ExchangeRekeyAsync`) và **L2TP control-channel** (interval + **cap** `L2tpMaxRetransmits`, mặc định 8×1s) thành cấu hình. [L2tpControlChannel.cs](../src/TqkLibrary.Vpn.L2tp/L2tpControlChannel.cs) thêm event `Failed` (mỗi message đếm `Attempts`; vượt cap → dừng timer + raise); [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs) chuyển `Failed`→`Fail`(mở khóa handshake)+`Disconnected`(kích reconnect). Library mặc định `maxRetransmits=0` (vô hạn — backward-compat); driver opt-in cap. Overload [`UseL2tpIpsec(reconnect, timeout)`](../src/TqkLibrary.Vpn/VpnClientBuilder.cs#L32). Test offline cap: [L2tpControlChannelTests.cs](../tests/TqkLibrary.Vpn.L2tp.Tests/L2tpControlChannelTests.cs).
    - [ ] **Chưa làm:** exponential-backoff cho khoảng retransmit (hiện cố định mỗi tick); SSTP `ReadPacketAsync` không có timeout chủ động (chỉ dừng khi TLS stream đóng/cancel).
- [ ] **Rủi ro forced-NAT-T theo server** (plan rủi ro #1): vài gateway từ chối ephemeral-port/forced-NAT → cần fallback **native ESP** (cần `Transport.RawIp`, elevate) + test nhiều server.

## P1 — Độ phủ test

- [x] **IKEv1 in-process two-party capstone**: full Main Mode MM1-6 (PSK) + Quick Mode QM1-3 chống `SimulatedResponderV1` hand-rolled, rồi ESP 2 chiều, cộng round-trip DPD + Delete — regression **offline** cho các trao đổi IKEv1 mã hóa trước đây chỉ live-test. → [tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/IkeV1HandshakeTests.cs](../tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/IkeV1HandshakeTests.cs)
- [x] **IpStack TCP in-process loopback test**: client active-open vs passive responder hand-rolled qua cặp kênh in-memory serialize — handshake, data echo, assert cumulative-ACK, active close, passive close. → [tests/TqkLibrary.Vpn.IpStack.Tests/TcpStackTests.cs](../tests/TqkLibrary.Vpn.IpStack.Tests/TcpStackTests.cs)
- [ ] **Lab thay cho server công khai**: SSTP/L2TP live test bám `public-vpn-227.opengw.net` → dễ flaky. Dựng **strongSwan/SoftEther Docker** cho CI ổn định.
- [x] **Fuzz/malformed parser**: IsakmpMessage V1 + IkeMessage V2 ([ParserFuzzTests.cs](../tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/ParserFuzzTests.cs)), L2TP codec ([L2tpCodecFuzzTests.cs](../tests/TqkLibrary.Vpn.L2tp.Tests/L2tpCodecFuzzTests.cs)), PPP HDLC ([HdlcFuzzTests.cs](../tests/TqkLibrary.Vpn.Ppp.Tests/HdlcFuzzTests.cs)), SSTP control codec + round-trip BuildBody↔Parse ([SstpControlCodecTests.cs](../tests/TqkLibrary.Vpn.Sstp.Tests/SstpControlCodecTests.cs)) — bơm gói rác để chắc không crash.

---

## P1/P2 — Follow-up sau khi tách driver + robustness SSTP

- [ ] **Test offline cho supervisor/keepalive/reconnect của SSTP**: cần một **transport seam** (factory `ISstpTransport`) để chèn transport giả lập — hiện supervisor SSTP **chỉ** được phủ qua live integration test + việc mirror mô hình L2TP đã được kiểm chứng. → [SstpConnection.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpConnection.cs), [SstpTransport.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpTransport.cs).
- [ ] **`SstpTransport.ConnectAsync` chưa honor `CancellationToken`** trong lúc TCP connect / TLS auth ([SstpTransport.cs:33-47](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpTransport.cs#L33-L47)): caller hủy giữa chừng connect hiện hiện ra dưới dạng `VpnConnectionException` bọc thay vì `OperationCanceledException`. Nhỏ, pre-existing.
- [ ] **`IkeV1Client.ProcessQuickMode2` không xác thực HASH(2) của responder** ([IkeV1Client.cs:205-216](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L205-L216)) — cố ý để interop rộng với nhiều gateway; ghi nhận như nợ bảo mật nhẹ.

---

## P2 — IP stack hoàn thiện

- [ ] **TCP retransmit/RTO** (RFC 6298) + **sliding window** thật + half-close edge cases. Hiện tối giản, dựa vào tunnel "đủ tin cậy" (no-SACK, no-retransmit). → [TcpConnection.cs](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs)
- [ ] **ICMP** (echo/ping, destination-unreachable) — chưa có. → [IpStack/](../src/TqkLibrary.Vpn.IpStack/)
- [ ] **IPv4 reassembly** cho gói phân mảnh inbound (hiện giả định không phân mảnh).
- [ ] **MTU/PMTUD**: MTU cố định 1400, chưa Path-MTU-Discovery.

## P2 — Nợ kỹ thuật & tài liệu

- [ ] **AEAD ESP (AES-GCM)**: `EspGcmSuite` đã có nhưng IKEv1/L2TP đang chỉ negotiate **AES-CBC+HMAC**; kể cả IKEv2 [`IkeProposals`](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeProposals.cs) cũng chỉ chào AES-CBC-256+HMAC-SHA-256 dù [`IkeTransformId`](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Enums/IkeTransformId.cs) đã có `AesGcm16=20` → bổ sung đề xuất GCM. → [EspGcmSuite.cs](../src/TqkLibrary.Vpn.Ipsec/Esp/EspGcmSuite.cs)
- [ ] **Hợp đồng mồ côi** (`IByteStreamTransport`, `ISecuritySession`, `IPacketEncapsulator`): khai báo trong `Abstractions` nhưng **không class nào implement/consume** — SSTP tự cuộn TLS riêng (`TcpClient`+`SslStream`) trong `SstpTransport`, ESP dùng `EspSession` riêng (không qua `ISecuritySession`). → refactor `SstpTransport` về sau `IByteStreamTransport` để biến interface thành thật + tái dùng cho SSL-VPN khác. → [IByteStreamTransport.cs](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs), [SstpTransport.cs](../src/TqkLibrary.Vpn.Drivers.Sstp/SstpTransport.cs)
- [ ] **IKEv2 Configuration Payload (CP)**: hiện chỉ `RawPayload`; cần model CP để nhận IP/DNS qua IKEv2 (chuẩn bị cho driver IKEv2-native). → [Ipsec/Ike/V2/Payloads/](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Payloads/)
- [ ] **Đồng bộ design docs 00–09 ↔ as-built**: doc `10` đã liệt kê khác biệt (L2TP dùng IKEv1 chứ không IKEv2; không có `EspIkeDemuxTransport`; chưa có L2 Ethernet…) → cập nhật/đánh dấu rõ design-intent.
- [ ] **Logging/diagnostics** xuyên suốt (trace handshake, drop reason).
- [ ] **Review** cancellation/timeout & thread-safety toàn cục (các receive-loop, channel).
- [ ] **CI đa OS** (plan M0) — chưa có cấu hình CI.
- [ ] **Adapter proxy** (hiện **inline** trong [`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo), chưa tách thành project `src/`): mới có `IConnectSource` (HTTP/SOCKS CONNECT). Còn thiếu **UDP-ASSOCIATE** (có sẵn `VpnUdpClient`, cần SOCKS5 UDP framing), **BIND** (cần listen userspace — chưa có), **DNS-over-tunnel** (đang resolve bằng host DNS), **IPv6**. Nếu cần tái dùng → cân nhắc tách lại thành `TqkLibrary.Vpn.Proxy`.
- [ ] **NuGet packaging** nếu phát hành: version (GitVersion), `GenerateDocumentationFile`, symbols/snupkg.

---

## P3 — Giao thức & tầng tương lai (theo plan "sau v1")

- [ ] **Driver IKEv2-native** (IPsec IKEv2 VPN, không qua L2TP): hạ tầng IKEv2 đã sẵn ([IkeClient.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeClient.cs)), cần driver + CP để cấp IP trực tiếp + ESP data plane (đã có).
- [ ] **Tầng L2 Ethernet** (multi-host): `EthernetSwitch` + `VirtualHost` + ARP responder + DHCP client → kích hoạt nhiều "máy LAN" cho OpenVPN-tap/SoftEther. Hiện mới chỉ có đường L3 (`IPacketChannel`).
- [ ] **Driver OpenVPN** (tun/tap, opcodes 1–11, NCP, PUSH_REPLY).
- [ ] **Driver SoftEther** (SSL-VPN, PACK codec, SHA-0/RC4, SecureNAT) — re-implement, không copy GPL source.
- [ ] **Driver WireGuard** (Noise IKpsk2, ChaCha20-Poly1305/X25519/BLAKE2s) → cần `Crypto.Noise`.
- [ ] **Driver OpenConnect-family** (Cisco/Fortinet/F5/Juniper/Pulse/GlobalProtect) → cần `Transport.Dtls`.
- [ ] **`Transport.Tcp` / `Transport.Tls`** (byte-stream transport độc lập, implement [`IByteStreamTransport`](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs)): tách phần TLS-over-TCP hiện đang nhúng trong `SstpTransport` ra project dùng chung, làm nền cho các SSL-VPN tương lai (SoftEther, OpenConnect-family). Hiện mới có interface, chưa có concrete.
- [ ] **`Transport.RawIp`** (opt-in, cần elevate, tự detect quyền root/CAP_NET_RAW vs Administrators) → PPTP/GRE/EtherIP/L2TPv3/native-ESP. Đi kèm `Crypto.Mppe` (RC4/MPPE) cho PPTP.

---

## Gợi ý thứ tự
1. ~~**Keepalive + rekey + teardown + reconnect** (P1)~~ — ✅ xong cho **cả 2 driver** (L2TP/IPsec: keepalive, Phase 2 rekey, teardown, auto-reconnect + Phase 1 by-reconnect; SSTP: active keepalive, teardown Call-Disconnect, auto-reconnect) + ~~typed exception~~ + ~~timeout cấu hình được + L2TP retransmit cap~~. **Còn lại P1 robustness**: forced-NAT-T fallback.
2. ~~**IKEv1 capstone + TCP loopback + fuzz parser**~~ (P1 test) — ✅ xong regression offline. **Còn lại**: lab Docker thay server công khai.
3. **TCP retransmit + ICMP + AES-GCM ESP** (P2) — vững IP stack & crypto.
4. **Driver IKEv2-native** (P3) — tận dụng hạ tầng IKEv2 đã build sẵn, chi phí thấp nhất trong nhóm P3.
5. Các driver/tầng còn lại theo nhu cầu.
