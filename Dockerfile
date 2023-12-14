# build the server binary
FROM golang:1.20 AS builder
LABEL stage=server-intermediate
WORKDIR /go/src/github.com/Infoblox-CTO/cdc.grpc-in
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/server ./cmd

FROM alpine:latest AS runner
ARG GIT_TAG
ARG GIT_SHA
LABEL Name="Infoblox-CTO/cdc.grpc-in" GitTag="$GIT_TAG" GitSha="$GIT_SHA"

ENV CONF_DIR=/opt/grpc_in/conf
ENV GRPC_IN_CONFIG=${CONF_DIR}/grpc_in.json
ENV IB_STATS_DIR=/infoblox/data/in/cloud
ENV STATS_BASE_DIR=/var/cache/cdc_metrics

ENV CONTAINER_NAME=grpc_in
ENV CONT_ID=cdc:grpcin
ENV ONPREM_MONITOR_PORT=8125
ENV LOG_LEVEL=INFO
ENV HOSTAPP_CONFIG=/etc/onprem.d/hostapp_config.json

ADD ./scripts/init.sh /usr/local/bin/
ADD ./scripts/supervisord.conf ${CONF_DIR}/

WORKDIR /usr/local/bin
COPY --from=builder /go/src/github.com/Infoblox-CTO/cdc.grpc-in/bin/server .

RUN apk update && \
    apk  add --no-cache ca-certificates wget supervisor && \
    mkdir -p ${CONF_DIR} && \
    mkdir -p ${STATS_BASE_DIR} && \
    chmod 755 /usr/local/bin/init.sh && \
    echo 0 > ${CONF_DIR}/version && \
    touch   ${GRPC_IN_CONFIG}

ENTRYPOINT ["/usr/local/bin/init.sh"]

HEALTHCHECK --interval=10s --timeout=20s --start-period=12s --retries=3 CMD wget --content-on-error=on -qO- http://127.0.0.1:10001/health