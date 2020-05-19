-Werror=implicit-function-declaration
CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)

OBJS = prc.o rbtree/rbtree.o
TARGET = output
obj-m      := $(TARGET).o
$(TARGET)-objs := $(OBJS)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
