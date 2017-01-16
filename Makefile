CC     = gcc
CFLAGS = -Wall
LIBS   = -lpcap

stroke:
	$(CC) $(CFLAGS) -o stroke stroke.c $(LIBS)

clean:
	rm -f stroke *core* *~ *.o

