# accel-ppp trên ubuntu:24.04 — SSTP + L2TP + PPTP, BẬT IPv6 (RA/SLAAC trên ppp).
#
# Gói `accel-ppp` KHÔNG có trong apt Ubuntu 24.04 (đã kiểm: "Unable to locate package")
# ⇒ build từ source (repo chính thức). Tắt build kernel-driver (ipoe/vlan-mon) để khỏi cần
# kernel headers; daemon userspace dùng module ppp/pptp/pppol2tp sẵn của host kernel.
# Recipe đã verify chạy được: cmake cần libpcre2-dev + libssl-dev; binary -> /usr/sbin/accel-pppd,
# module -> /usr/lib64/accel-ppp.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Build deps + runtime deps trong một layer (cache được khi config đổi).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake git pkg-config \
      libssl-dev libpcre2-dev \
      openssl iproute2 iputils-ping ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/accel-ppp/accel-ppp.git /tmp/accel-ppp \
 && cmake -S /tmp/accel-ppp -B /tmp/accel-ppp/build \
      -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE \
      -DLUA=FALSE -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/accel-ppp/build -j"$(nproc)" \
 && cmake --install /tmp/accel-ppp/build \
 && rm -rf /tmp/accel-ppp

RUN mkdir -p /etc/accel-ppp/certs /var/log/accel-ppp

COPY accel-ppp.conf /etc/accel-ppp.conf
COPY chap-secrets   /etc/ppp/chap-secrets
COPY entrypoint.sh  /usr/local/bin/entrypoint.sh
RUN chmod 600 /etc/ppp/chap-secrets \
 && chmod +x /usr/local/bin/entrypoint.sh

# SSTP 443/tcp, PPTP 1723/tcp, L2TP 1701/udp (network_mode: host nên EXPOSE chỉ là tài liệu)
EXPOSE 443/tcp 1723/tcp 1701/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
