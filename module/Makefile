obj-m += nat46.o
nat46-objs := nat46-netdev.o nat46-module.o nat46-core.o nat46-glue.o
CFLAGS_nat46.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
