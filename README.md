

# Generate vmlinux.h

- `git clone --recurse-submodules https://github.com/libbpf/bpftool.git`
- `docker build -f Dockerfile -t bpftool`
- `docker run bpftool  btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`

# Compile ebpf program 

- `clang -g -target bpf -I./src/include  -I./libbpf/src -c src/syscall.bpf.c -o build/syscall.bpf.o `

# Generate eBPF skeleton

-  `docker run -v $(pwd)/build:/build bpftool gen skeleton build/syscall.bpf.o > src/syscall.skel.h`

# Compile the loader/collector

docker run --rm -it --privileged \
-v $(pwd):/ebpf-ring-buffer  -v /sys/kernel/btf:/sys/kernel/btf \
ubuntu:22.04 bash

clang -g -target bpf -I./src/include  -I./libbpf/src -c src/syscall.bpf.c -o build/syscall.bpf.o

gcc -o build/collector src/collector.c -I./src/include -I/usr/include/bpf -lbpf

clang -g -O2 -target bpf -I./libbpf/src   -I./src/include  -c src/syscall.bpf.c -o build/syscall.bpf.o
bpftool gen skeleton build/syscall.bpf.o > src/syscall.skel.h
gcc -o build/collector src/collector.c -I./libbpf/src -I./src/include -I/usr/include/bpf -L./libbpf/src -lbpf -lelf -lz

ok but first build libbpf cd src then make then finally make install 
install bpftool 
clang -g -O2 -target bpf -I./libbpf/src   -I./src/include  -c src/syscall.bpf.c -o build/syscall.bpf.o
docker run -v $(pwd)/build:/build bpftool gen skeleton build/syscall.bpf.o > src/syscall.skel.h
gcc -o build/collector src/collector.c -I./libbpf/src -I./src/include -I/usr/include/bpf -L./libbpf/src -lbpf -lelf -lz
LD_LIBRARY_PATH=./libbpf/src ./build/collector


1- docker run --rm -it --privileged \
-v $(pwd):/ebpf-ring-buffer \
ubuntu:22.04 bash
2-cd ebpf-ring-buffer/ebpf-ring-buffer
3- apt-get update && apt-get install -y clang llvm make cmake gcc git libelf-dev pkg-config
4- cd bpftool/src - make - make install
5- cd libbpf/src - make - make install
5- clang -g -O2 -target bpf -I./libbpf/src   -I./src/include  -c src/syscall.bpf.c -o build/syscall.bpf.o
6- bpftool gen skeleton build/syscall.bpf.o > src/syscall.skel.h
7- LD_LIBRARY_PATH=./libbpf/src ./build/collector



mount -t debugfs none /sys/kernel/debug
LD_LIBRARY_PATH=./libbpf/src ./build/collector


