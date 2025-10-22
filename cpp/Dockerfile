# Build stage
FROM debian:12 AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential cmake pkg-config libssl-dev ca-certificates &&     rm -rf /var/lib/apt/lists/*
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release &&     cmake --build build -j &&     cmake --install build --prefix /install

# Runtime stage
FROM debian:12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates &&     rm -rf /var/lib/apt/lists/*
COPY --from=build /install/bin/otto-demo /usr/local/bin/otto-demo
COPY --from=build /install/bin/otto-cli /usr/local/bin/otto-cli
CMD ["otto-demo", "--help"]
