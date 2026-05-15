FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LLVM_VERSION=17

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      clang-17 \
      llvm-17 \
      libclang-rt-17-dev \
      libfuzzer-17-dev \
      ruby \
      ruby-dev \
      build-essential \
      libssl-dev \
      pkg-config \
      rsync \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    for name in cc gcc clang \
                aarch64-linux-gnu-gcc x86_64-linux-gnu-gcc \
                aarch64-linux-gnu-g++ x86_64-linux-gnu-g++; do \
        ln -sf /usr/bin/clang-17 /usr/local/bin/$name; \
    done; \
    for name in c++ g++ clang++; do \
        ln -sf /usr/bin/clang++-17 /usr/local/bin/$name; \
    done

ENV CC=clang-17 \
    CXX=clang++-17 \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PQCRYPTO_NATIVE_ASM=0 \
    PQCRYPTO_NATIVE_ARITH=0 \
    PQCRYPTO_NATIVE_FIPS202=0

WORKDIR /work
