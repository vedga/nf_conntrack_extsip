obj-m += nf_conntrack_extsip.o

nf_conntrack_extsip-objs :=				\
	./src/nf_conntrack_extsip.o			\
	./src/callinfo.o				\
	./src/procfs_calls.o				\
	./src/dpi_sip.o
	
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
