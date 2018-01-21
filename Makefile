#Makefile
all: airodump-ng

airodump-ng: airodump-ng.o
	g++ -o airodump-ng airodump-ng.o -lpcap 

airodump-ng.o: airodump-ng.cpp
	g++ -c -o airodump-ng.o airodump-ng.cpp -lpcap

clean:
	rm -f airodump-ng
	rm -f *.o
