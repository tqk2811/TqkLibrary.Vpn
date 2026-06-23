# =====================================================================
# lab/l2tp-nonat — L2TP/IPsec server bằng strongSwan (IKEv1 PSK + ESP
# transport) + xl2tpd + pppd CHUẨN. Validate LIVE P0.8c (native ESP
# proto-50, no-NAT) của driver L2TP/IPsec repo TqkLibrary.
#
# Vì sao ubuntu:22.04 (KHÔNG 24.04): 22.04 còn strongSwan starter/ipsec.conf
# (legacy, dễ cấu hình no-NAT/forceencaps) + xl2tpd trong apt. 24.04 có nguy
# cơ chỉ còn swanctl (phải viết lại config) — tránh rủi ro đó cho lab này.
#
# Vì sao pppd CHUẨN (KHÔNG accel-ppp): accel-ppp HỎNG PPP network-phase
# (không gửi IPCP ConfReq — lỗi FSM userspace, xem lab/README-vi.md §7.6).
# xl2tpd spawn pppd CHUẨN cho mỗi phiên L2TP ⇒ IPCP/IPV6CP lên đúng.
#
# An toàn: chạy trên bridge tùy biến (KHÔNG host-net, KHÔNG privileged-host)
# ⇒ strongSwan đụng XFRM chỉ trong netns container, không phá mạng VM
# (lab cũ host-net từng làm SẬP mạng VM — lab/README-vi.md §7.5).
# =====================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-starter \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        xl2tpd \
        ppp \
        iproute2 \
        iptables \
        tcpdump \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- strongSwan config (IKEv1 PSK + ESP transport, forceencaps=no) ---
COPY ipsec.conf      /etc/ipsec.conf
COPY ipsec.secrets   /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf

# --- xl2tpd + pppd config ---
COPY xl2tpd.conf     /etc/xl2tpd/xl2tpd.conf
COPY options.xl2tpd  /etc/ppp/options.xl2tpd
COPY chap-secrets    /etc/ppp/chap-secrets

COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

RUN chmod 600 /etc/ipsec.secrets /etc/ppp/chap-secrets \
    && chmod +x /usr/local/bin/entrypoint.sh \
    # xl2tpd cần thư mục control + run; tạo sẵn tránh lỗi "No such file".
    && mkdir -p /var/run/xl2tpd \
    # Gỡ plugin kernel-libipsec: nó đòi /dev/net/tun (không mount trong container) → load NULL
    # → charon ABORT khi khởi động (đã gặp live). Ta dùng kernel-netlink (XFRM thật trong netns
    # container) nên KHÔNG cần libipsec. Gỡ cả .so lẫn file conf để charon không thử nạp.
    && rm -f /usr/lib/ipsec/plugins/libstrongswan-kernel-libipsec.so \
             /etc/strongswan.d/charon/kernel-libipsec.conf

# IKE 500/udp + (NAT-T 4500/udp khi float — nhưng P0.8c mong KHÔNG float).
# ESP proto-50 KHÔNG phải cổng (không EXPOSE được) — đi L2 thẳng trên bridge.
# KHÔNG publish ra ngoài: test nội bộ bridge giữa 2 container.
EXPOSE 500/udp 4500/udp 1701/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ---------------------------------------------------------------------
# CHECK: nếu apt 22.04 đổi tên gói (vd 'strongswan-starter' gộp vào
#        'strongswan'), bỏ dòng thừa. Binary mong đợi: /usr/sbin/ipsec,
#        /usr/sbin/xl2tpd, /usr/sbin/pppd.
# ---------------------------------------------------------------------
