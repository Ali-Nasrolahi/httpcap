HARD_DISK := iso/alpine.img

all: build

build:
	@echo Building pcap capturer
	gcc -lpcap pcap/capture.c -o pcap_capturer
	@echo Building netfilter module
	$(MAKE) -C netf

start_env: clean setup mir server client

server:
	sudo qemu-kvm -m 1G -hda $(HARD_DISK) -snapshot \
		-device e1000,mac=50:54:00:00:00:91,netdev=lan,id=lan \
		-netdev tap,id=lan,ifname=tap0,script=no,downscript=no &

client:
	sudo qemu-kvm -m 1G -hda $(HARD_DISK) -snapshot \
		-device e1000,mac=50:54:00:00:00:92,netdev=lan,id=lan \
		-netdev tap,id=lan,ifname=tap1,script=no,downscript=no &

setup: tap
	sudo ovs-vsctl add-br br0
	sudo ovs-vsctl add-port br0 tap0
	sudo ovs-vsctl add-port br0 tap1
	sudo ovs-vsctl add-port br0 capture

tap:
	sudo ip tuntap add tap0 mode tap
	sudo ip tuntap add tap1 mode tap
	sudo ip l add capture type dummy
	sudo ip l s up tap0
	sudo ip l s up tap1
	sudo ip l s up capture

mir:
	sudo ovs-vsctl --id=@p get port capture \
    -- --id=@m create mirror name=m0 select-all=true output-port=@p \
    -- set bridge br0 mirrors=@m

clean:
	- sudo ovs-vsctl del-br br0
	- sudo ip l d tap1
	- sudo ip l d tap0
	- sudo ip l d capture
	- rm pcap_capturer
	$(MAKE) -C netf clean

