KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += undebug.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

test: all
	sudo insmod *ko
	sudo dmesg | tail
	sudo rmmod *ko
