FROM golang:1-alpine AS build

RUN apk update && apk add make git gcc musl-dev

ADD . /go/src/github.com/povilasv/systemd_exporter

WORKDIR /go/src/github.com/povilasv/systemd_exporter

ENV GO111MODULE on
RUN make build
RUN mv systemd_exporter /systemd_exporter

FROM quay.io/prometheus/busybox:glibc

COPY --from=build systemd_exporter /bin/systemd_exporter
RUN chown -R nobody /bin/systemd_exporter

EXPOSE      9558
USER        nobody
ENTRYPOINT  ["/bin/systemd_exporter"]
