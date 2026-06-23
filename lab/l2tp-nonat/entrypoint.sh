#!/bin/sh
# entrypoint lab/l2tp-nonat — chạy strongSwan (charon) NỀN + xl2tpd FOREGROUND.
# (chmod +x do Dockerfile xử lý: RUN chmod +x /usr/local/bin/entrypoint.sh)
#
# Thứ tự: bật forwarding/rp_filter -> start ipsec (charon) nền -> chờ charon
# sẵn sàng -> exec xl2tpd -D (foreground, giữ container sống).
set -e

echo "[entrypoint] lab/l2tp-nonat — strongSwan + xl2tpd + pppd"
ipsec --version 2>/dev/null || true

# --- forwarding trong netns container (an toàn: chỉ tác động netns này) ---
# compose cũng đặt qua sysctls: nhưng lặp lại cho chắc khi chạy độc lập.
sysctl -w net.ipv4.ip_forward=1          >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
# Tắt rp_filter để ESP transport không bị drop bởi reverse-path (live hay vướng).
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# --- xl2tpd cần /dev/ppp + thư mục control ---
# CHECK: /dev/ppp phải tồn tại (compose mount devices: /dev/ppp; host VM phải
#        'modprobe ppp_generic' TRƯỚC). Nếu thiếu -> xl2tpd báo "Cannot open /dev/ppp".
if [ ! -c /dev/ppp ]; then
    echo "[entrypoint][WARN] /dev/ppp KHÔNG tồn tại. Host VM cần: sudo modprobe ppp_generic" >&2
fi
mkdir -p /var/run/xl2tpd

# --- start strongSwan charon ở NỀN ---
# 'ipsec start' (KHÔNG --nofork): khởi động starter+charon ở nền rồi trả về,
# để ta giữ xl2tpd làm tiến trình foreground của container.
# CHECK: nếu bản này dùng systemd-only, thử '/usr/lib/ipsec/starter --daemon charon'.
ipsec start
echo "[entrypoint] đợi charon sẵn sàng..."
# Chờ ngắn để charon nạp ipsec.conf (auto=add conn l2tp-psk-nonat) trước khi nhận client.
i=0
while [ $i -lt 10 ]; do
    if ipsec status >/dev/null 2>&1; then
        break
    fi
    i=$((i+1))
    sleep 1
done
ipsec statusall 2>/dev/null || true

# --- exec xl2tpd FOREGROUND (-D) — giữ container sống, log ra stdout/stderr ---
echo "[entrypoint] starting xl2tpd (foreground)..."
exec xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf
