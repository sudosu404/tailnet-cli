FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY main.go .
RUN go mod init backend && go build -o backend main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/backend .

CMD ["./backend"]