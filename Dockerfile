FROM ubuntu:22.04

WORKDIR /ebpf-ring-buffer

RUN apt-get update && \
    apt-get install -y clang llvm make cmake gcc git libelf-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY bpftool /ebpf-ring-buffer/bpftool
COPY libbpf /ebpf-ring-buffer/libbpf
COPY src /ebpf-ring-buffer/src

RUN cd /ebpf-ring-buffer/bpftool/src && make && make install
RUN cd /ebpf-ring-buffer/libbpf/src && make && make install
RUN mkdir -p /ebpf-ring-buffer/build
RUN clang -g -O2 -target bpf -I./libbpf/src -I./src/include \
    -c src/syscall.bpf.c -o bgit remote set-url originuild/syscall.bpf.o
RUN bpftool gen skeleton build/syscall.bpf.o > src/syscall.skel.h
RUN gcc -o build/collector src/collector.c \
    -I./libbpf/src -I./src/include -I/usr/include/bpf \
    -L./libbpf/src -lbpf -lelf -lz
ENV LD_LIBRARY_PATH=./libbpf/src

CMD ["/bin/sh", "-c", "mount -t debugfs none /sys/kernel/debug && ./build/collector"]
