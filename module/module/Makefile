obj-m += hw4secws.o
hw4secws-objs :=	./rule_table_module/rule_table_module.o 	./hook_module/hook_module.o	./reset_log_module/reset_log_module.o	./connections_module/connections_module.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
