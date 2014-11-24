# Time-stamp: <02/11/09 10:40:24 INGA>
# File: Makefile
#packetsize

CFLAGS  += -Wall -g -O0
LDFLAGS +=
PREFIX=/usr/local
OBJECTd= tgtrace.o
targetd= tgtrace

all: $(OBJECTd)	
	$(CC) -o $(targetd) $(LDFLAGS) $(OBJECTd) $(shell pkg-config libcap_utils-0.7 libcap_filter-0.7 --libs) -lqd

clean:
	rm -f *.o $(OBJECTd)

install: tgtrace
	install -m 0755 tgtrace $(PREFIX)/bin

tgtrace.o: tgtrace.c 
	$(CC) $(CFLAGS) $(shell pkg-config libcap_stream-0.7 --cflags) -c tgtrace.c 

