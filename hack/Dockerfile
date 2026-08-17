FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine3.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-w -s" -o bin/kfuzz .

FROM docker.io/library/alpine:3.23

COPY --from=builder /app/bin/kfuzz /usr/local/bin/kfuzz

CMD ["/usr/local/bin/kfuzz"]

