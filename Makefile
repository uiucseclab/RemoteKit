obj-m += rootkit.o

all: rootkit.ko

rootkit.ko: rootkit.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: uninstall
uninstall:
	-sudo rmmod rootkit

.PHONY: install
install: rootkit.ko uninstall
	sudo insmod rootkit.ko

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
