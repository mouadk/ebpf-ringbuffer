# eBPF ring buffer 
This repository houses a bpf program populating a ring buffer. The program is loaded and deployed using 
libbpf API. Next, it is drained using epoll-based API. 

I have included a docker file used to test the deployment (don't forget to use `git clone --recurse-submodules` when cloning). To build the image run ` docker build -t ebpf-collector .`
Next, you can run the image as follows `docker run --rm -it --privileged ebpf-collector`.
You can then access logs inside the container (`file_access.log`). 
e.g.

```
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods/cgroup.procs
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods/besteffort
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods/burstable
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods/besteffort
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods/burstable
pid=853, comm=kubelet, filename=/sys/fs/cgroup/kubepods/kubepods
``` 
If you want to learn more about ebpf ring buffer, you can have a look at my blog post: 

For more examples, you can have a look at: https://github.com/libbpf/libbpf-bootstrap/tree/master/examples.