FROM ghcr.io/sagernet/sing-box:v1.14.4@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279
RUN apk add --no-cache iproute2 iptables
COPY start.sh /opt/ethernet-start.sh
ENTRYPOINT ["/bin/sh", "/opt/ethernet-start.sh"]
