CC = gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
LDFLAGS = -ldl
PROGS	= sandbox.so
SHARED = sandbox
.PHONY: clean
all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: sandbox.o
	$(CC) -o $@ -shared $^ $(LDFLAGS)

cleanup:
	rm -f *.o
clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__
	rm -f *read.log
	rm -f *write.log
	rm index.html.*