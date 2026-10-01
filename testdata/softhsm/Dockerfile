FROM golang:1.26.7-bookworm AS go
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2=2.6.1-2.2ubuntu3 libsofthsm2=2.6.1-2.2ubuntu3 libsofthsm2-dev=2.6.1-2.2ubuntu3 \
    gcc libc6-dev ca-certificates python3 git && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH
