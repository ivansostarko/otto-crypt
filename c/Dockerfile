# Build stage
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential cmake pkg-config libssl-dev ca-certificates &&     rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates &&     rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/otto-demo /usr/local/bin/otto-demo
COPY --from=build /src/build/otto-cli  /usr/local/bin/otto-cli
ENTRYPOINT ["/usr/local/bin/otto-demo"]
CMD ["--help"]
