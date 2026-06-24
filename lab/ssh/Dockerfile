# Lab V.10: OpenSSH server with PermitTunnel point-to-point for VPN-over-SSH (OpenSSH `-w` tun).
# Ubuntu 24.04 + openssh-server + iproute2 + tcpdump. The entrypoint (setup-server.sh) writes sshd_config,
# creates the tun device node, installs the client's authorized_key + a tunnel user, brings up tunN with the
# gateway IP when it appears, then runs sshd in the foreground in debug mode.
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server iproute2 iputils-ping tcpdump python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

# The entrypoint is mounted from the lab dir at run time (see docker-compose.yml).
CMD ["/bin/sh", "-c", "exec /lab/setup-server.sh"]
