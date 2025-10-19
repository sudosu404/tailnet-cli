FROM alpine:3.22

RUN apk --no-cache add ca-certificates
COPY tailnet /usr/local/bin/tailnet
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/tailnet"]