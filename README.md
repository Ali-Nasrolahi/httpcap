# HTTP Cap

- Finding HTTP Packets and log them with different solutions
- Solutions:

  - `libpcap` + Open vSwitch port mirroring (`SPAN`) on a dummy device. Check `Makefile` for demo setup
  - `netfilter` kernel module to find HTTP Packets and logs its payload

Build `libpcap` snippet and `Netfilter` lkm with:

```bash
make
```

## `libpcap`

Works with demo environment with `qemu/kvm` and binds to dummy interface.

## `Netfilter`

Works for all traffic that goes through Linux network stack and attaches to `NF_INET_PRE_ROUTING` and `NF_INET_POST_ROUTING` hooks.

## Environment

You can both use container and virtual machine environment for testing. if you're using `Netfilter` both environments should work fine.
By using `libpcap` and containers, you need to attach the `veth` of the container to Open vSwitch bridge you defined.
