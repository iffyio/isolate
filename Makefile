PROG=isolate
CFLAGS=-I

%.o: %.c
	gcc -c -o $@ $<

compile: $(PROG).o
	gcc -o $(PROG) $(PROG).o
