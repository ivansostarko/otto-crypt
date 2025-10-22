# Build stage
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/otto-demo ./demo

# Runtime stage (distroless or alpine). Use alpine for shell friendliness.
FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
WORKDIR /home/app
COPY --from=build /out/otto-demo /usr/local/bin/otto-demo
ENTRYPOINT ["/usr/local/bin/otto-demo"]
CMD ["--help"]
