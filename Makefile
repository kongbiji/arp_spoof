CC	   = g++
CFLAGS = -g -Wall
OBJS   = arp_spoof.o
TARGET = arp_spoof

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

arp_spoof.o: parse.h function.h arp_spoof.cpp

clean:
	rm -rf *.o $(TARGET)
