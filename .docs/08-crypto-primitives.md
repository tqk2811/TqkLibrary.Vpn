# 08 — Crypto primitives: có sẵn vs tự viết

> Cô lập trong family `TqkLibrary.VpnClient.Crypto.*` sau interface (`Crypto.Abstractions`) để façade & driver không phụ thuộc chi tiết framework. netstandard2.0 thiếu nhiều API → ẩn sau shim.

> **[As-built]** Lệch tổ chức (xem [`10`](10-codebase-architecture-and-flow.md) §5 + [README Crypto](../src/TqkLibrary.VpnClient.Crypto/README-vi.md)):
> tất cả nằm trong **một project** [`TqkLibrary.VpnClient.Crypto`](../src/TqkLibrary.VpnClient.Crypto) — `Crypto.Aead`/`Crypto.Mppe`/
> `Crypto.Noise` ở cột "DLL" thực ra là **sub-namespace**, không có project `Crypto.Abstractions` tách riêng (interface để ngay
> trong `Crypto/Interfaces`). **BouncyCastle.Cryptography** nay ref **không điều kiện** cả 2 TFM (net8 lẫn ns2.0 đều thiếu
> X25519/BLAKE2s/ChaCha20-Poly1305-ns2.0). Code `#if` rào theo phiên bản .NET **thấp nhất** hỗ trợ (vd ChaCha20-Poly1305 BCL
> native từ **net5+**, không phải net8). Các primitive đã hiện thực + KAT: MD4/DES/AES-CTR/AES-GCM-shim/DH/SHA-0/RC4/MPPE/
> Tls1Prf/ChaCha20-Poly1305/X25519/BLAKE2s/HMAC-BLAKE2s/Noise-KDF/NoiseSymmetricState.

## Bảng tổng hợp

| Thuật toán | Dùng cho | net8.0 | netstandard2.0 | Hành động | DLL |
|---|---|---|---|---|---|
| MD4 | MS-CHAPv2 (NT-hash) | ❌ | ❌ | **Tự viết** (RFC 1320) | Crypto |
| DES (ECB) | MS-CHAPv2 (3×DES) | ✅ `DES` | ✅ | Built-in | Crypto |
| MD5 | CHAP, vài chỗ IKE | ✅ | ✅ | Built-in | Crypto |
| SHA1/256/384/512 | PRF, integrity | ✅ | ✅ | Built-in | Crypto |
| HMAC-SHA1/256/512 | IKE PRF, ESP integ | ✅ | ✅ | Built-in | Crypto |
| AES-CBC | ESP, IKE enc | ✅ `Aes` | ✅ | Built-in | Crypto |
| AES-CTR | ESP (vài profile) | ❌ trực tiếp | ❌ | **Tự dựng** từ AES-ECB | Crypto |
| AES-GCM | ESP/IKE AEAD | ✅ `AesGcm` | ❌ | **Shim** (BouncyCastle fallback) | Crypto.Aead |
| DH MODP group 2/14 | IKE key exchange | `BigInteger` | +`System.Numerics` | **Tự viết** modexp | Crypto |
| ECDH group 19/20 | IKEv2 modern | ✅ `ECDiffieHellman` | hạn chế | Hoãn (group 14 đủ v1) | Crypto |
| RNG | nonce, IV | ✅ `RandomNumberGenerator` | ✅ | Built-in | Crypto |
| **SHA-0** | SoftEther password | ❌ | ❌ | **Tự viết** (SHA-1 bỏ rotate msg-schedule) | Crypto |
| **RC4** | SoftEther data / MPPE | ❌ | ❌ | **Tự viết** / BouncyCastle | Crypto.Mppe |
| MPPE/MPPC (RC4 stateful) | PPTP, SSTP-opt | ❌ | ❌ | **Tự viết** (RFC 3078) + RFC3079 key-derive | Crypto.Mppe |
| ChaCha20-Poly1305 | WireGuard/Nebula | ✅ (net5+) | ❌ | BouncyCastle | Crypto.Noise |
| X25519/Curve25519 | WireGuard/Nebula | một phần | ❌ | BouncyCastle/Noise.NET | Crypto.Noise |
| BLAKE2s, HKDF, SipHash24 | WireGuard | ❌/một phần | ❌ | BouncyCastle/tự viết | Crypto.Noise |
| Ed25519 | Nebula/ZeroTier cert | ✅ (net7+) | ❌ | BouncyCastle | Crypto.Noise |
| AES-GMAC-SIV | ZeroTier | ❌ | ❌ | hand-port (out of scope v1) | — |

## Phải tự viết (phase 1 cần ngay)
- **MD4** — cho MS-CHAPv2 NT-hash. Có test vector RFC 1320.
- **AES-CTR** — dựng từ AES-ECB (counter mode), nếu transform ESP cần.
- **AES-GCM shim** — `IAeadCipher`: net8 dùng `AesGcm`, ns2.0 dùng BouncyCastle `GcmBlockCipher`.
- **DH modexp** — group 2 (1024) / 14 (2048) qua `BigInteger.ModPow`.

## Test vectors
- MS-CHAPv2: RFC 2759 §D (sample). MD4: RFC 1320. DH: RFC 3526. AES-GCM: NIST GCM KAT. SHA-0: FIPS 180 (original).

## Lưu ý netstandard2.0
- Thêm package: `System.Memory`, `System.IO.Pipelines`, `System.Buffers`, `System.Numerics.Vectors`, `Portable.BouncyCastle`/`BouncyCastle.Cryptography`.
- Cô lập code net8-only sau `#if NET8_0_OR_GREATER`.

> **[As-built]** Không rào cứng `#if NET8_0_OR_GREATER`: rào theo phiên bản .NET **thấp nhất** hỗ trợ API (vd `AesGcm`/
> `ChaCha20Poly1305` BCL có từ **net5+** ⇒ `#if NET5_0_OR_GREATER`), để code dùng được trên nhiều TFM hơn. `record`/`init`/
> `required` dùng được cả 2 TFM nhờ package source-only `TqkLibrary.CompilerServices`. Xem [CLAUDE.md](../CLAUDE.md).
