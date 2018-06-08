CPPFLAGS=-std=c++11 -Wall -I ../include -g
OBJ=eth_util.o arp_util.o ip_util.o icmp_util.o vm.o hypervisor.o
PROG=tap-lab

all: $(PROG)

$(PROG): $(OBJ) tap-lab.cpp
	g++ $(CPPFLAGS) -o $(PROG) tap-lab.cpp $(OBJ) -lpthread

eth_util.o: eth_util.cpp ../include/eth_util.h
	g++ $(CPPFLAGS) -c eth_util.cpp

arp_util.o: arp_util.cpp ../include/arp_util.h
	g++ $(CPPFLAGS) -c arp_util.cpp

ip_util.o: ip_util.cpp ../include/ip_util.h
	g++ $(CPPFLAGS) -c ip_util.cpp

icmp_util.o: icmp_util.cpp ../include/icmp_util.h
	g++ $(CPPFLAGS) -c icmp_util.cpp

vm.o: vm.cpp ../include/vm.h
	g++ $(CPPFLAGS) -c vm.cpp

hypervisor.o: hypervisor.cpp ../include/hypervisor.h ../include/vm.h
	g++ $(CPPFLAGS) -c hypervisor.cpp
clean:
	rm -f *.o $(PROG)

