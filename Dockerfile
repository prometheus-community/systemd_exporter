FROM quay.io/prometheus/busybox:glibc

COPY systemd_exporter /bin/systemd_exporter

EXPOSE      9557
USER        nobody
ENTRYPOINT  ["/bin/systemd_exporter"]
