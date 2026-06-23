# =====================================================================
# lab/openconnect — ocserv (OpenConnect server) tự host để VALIDATE LIVE
# driver V.5 OpenConnect của TqkLibrary (Drivers.OpenConnect / protocol
# OpenConnect / Transport.Dtls): interop thật với ocserv (Cisco AnyConnect
# compatible), kiểm soát TLS (CSTP) + DTLS data path + DPD/rekey.
#
# Vì sao container (KHÔNG host-net/privileged-host) — giống lab ikev2/wireguard/openvpn:
#   - ocserv tạo TUN trong netns container (CHỈ cần /dev/net/tun + NET_ADMIN),
#     KHÔNG đụng mạng VM, KHÔNG cần kernel module riêng.
#   - 2 container cùng bridge 'labnet' -> client gửi gói tới server qua tên
#     service. KHÔNG publish cổng ra ngoài: test nội bộ bridge.
#
# Server sinh self-signed cert + tạo user bằng ocpasswd lúc khởi động, build
# ocserv.conf (tcp-port=443 CSTP, udp-port=443 DTLS, ipv4-network 10.70.0.0/24,
# dns 1.1.1.1, cisco-client-compat=true, dtls-legacy=true). Demo .NET connect
# bằng URI openconnect://user:pass@ocserv-server (cert tự-ký ⇒ accept-any).
# =====================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ocserv \
        gnutls-bin \
        openssl \
        iproute2 \
        iptables \
        iputils-ping \
        socat \
        python3 \
        dnsmasq \
        tcpdump \
        rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# ocserv: CSTP trên TCP/443 + DTLS trên UDP/443. KHÔNG publish ra ngoài: test nội bộ bridge.
EXPOSE 443/tcp 443/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
