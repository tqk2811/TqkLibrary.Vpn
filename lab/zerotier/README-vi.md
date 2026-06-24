# lab/zerotier — V.7.3 ZeroTier live-validation (STAGED)

Scaffold để **validate live** protocol layer ZeroTier V.7.3 ([`src/TqkLibrary.VpnClient.ZeroTier`](../../src/TqkLibrary.VpnClient.ZeroTier))
khi **VM lab lên** (`ssh vpnlab`). Phiên tạo project này **VM down** nên phần interop còn **UNVERIFIED** — đây là bộ
công cụ chạy ngay khi VM khả dụng.

> **Trạng thái:** scaffold sẵn, **CHƯA chạy** (VM lab down 2026-06-24). Salsa20 nền đã KAT ECRYPT chuẩn offline;
> address derivation + VL1/VL2 wire cần đối chiếu ZeroTier thật.

## Cần đối chiếu (UNVERIFIED chờ live)

1. **Address derivation** — `ZeroTierAddressDerivation` (memory-hard SHA-512 + Salsa20/20 + genmem 2MB) byte-exact
   với `zerotier-idtool` thật. Hiện chỉ test self-consistency offline; **chưa KAT** vì không có identity mẫu.
2. **VL1 packet wire** — offset header, key-stream split (poly key = block 0), nửa-MAC truncate, KBKDF gói — đối chiếu
   `zerotier-one` thật (gửi/nhận HELLO). Cần driver phase (b) (UDP transport) hoặc harness 1-shot.
3. **VL2 FRAME + DeriveMac** — layout FRAME body + MAC per-network với node thật.

## Bước 1 — KAT address derivation (chạy được NGAY khi VM lên, không cần driver)

```bash
cd lab/zerotier
docker compose build
docker compose run --rm idtool /lab/gen-identity.sh /shared
# -> /shared/identity.json: { address, publicKeyHex (128 hex = 64B), identityString }
```

Lấy `publicKeyHex` + `address` nạp vào KAT (thêm test vào
[`ZeroTierAddressDerivationTests`](../../tests/TqkLibrary.VpnClient.ZeroTier.Tests/ZeroTierAddressDerivationTests.cs)):

```csharp
var pub = Convert.FromHexString("<publicKeyHex>");
var addr = new ZeroTierAddressDerivation().ComputeAddress(pub);
Assert.Equal("<address>", addr.ToString());   // KAT vs zerotier-idtool
```

- **Khớp** ⇒ memory-hard hash đúng byte-exact ⇒ gỡ "UNVERIFIED" cho identity.
- **Lệch** ⇒ sửa thứ tự genmem fill/shuffle hoặc split key/iv của Salsa20/20 trong
  [`ZeroTierAddressDerivation`](../../src/TqkLibrary.VpnClient.ZeroTier/Identity/ZeroTierAddressDerivation.cs) (bug
  interop điển hình — như bài học V.1–V.6). Đối chiếu thêm `zerotier-idtool getpublic`/`validate`.

## Bước 2 — VL1 HELLO interop (chờ driver phase b hoặc harness UDP)

Khi có UDP transport: dựng 1 node `zerotier-one` (join 1 network controller, có thể self-host controller bằng chính
`zerotier-one` + `ztncui`/API), gửi VL1 HELLO từ harness .NET tới node, đối chiếu node log + reply OK. Đây là phase (b)
— scaffold compose đã cấp `NET_ADMIN` + `/dev/net/tun` cho `zerotier-one`.

## Ghi chú

- **KHÔNG copy source ZeroTier** (BSL/proprietary) — chỉ dùng binary `zerotier-one`/`zerotier-idtool` để đối chiếu
  hành vi; protocol layer là clean-room từ mô tả spec/prose.
- **KHÔNG commit** identity keys (`.gitignore` đã chặn `identity.*` + `harness-bin/`).
