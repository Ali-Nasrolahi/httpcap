obj-m += httpf.o

KERNEL_SRC = /lib/modules/$(shell uname -r)/source

all:
	make -C $(KERNEL_SRC) M=$(shell pwd) modules

clean:
	make -C $(KERNEL_SRC) M=$(shell pwd) clean

format:
	clang-format -i -style=file *.c

load: unload all
	sudo insmod httpf.ko

unload:
	- sudo rmmod httpf
