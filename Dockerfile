ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/systemd_exporter /bin/systemd_exporter

EXPOSE      9558
USER        nobody
ENTRYPOINT  ["/bin/systemd_exporter"]
