#include <hypervisor.h>
#include <vm.h>
#include <iostream>
using namespace std;

int main() {
    Hypervisor hypervisor;

    string mac1 = "00:00:00:00:00:01";
    string ip1 = "192.168.1.1";
    VirtualMachine *vm1 = hypervisor.createVM(mac1, ip1);

    string mac2 = "00:00:00:00:00:02";
    string ip2 = "192.168.1.2";

    VirtualMachine *vm2 = hypervisor.createVM(mac2, ip2);
    // Wait for the VM to start
    this_thread::sleep_for (std::chrono::seconds(1));
    // Ping VM2 from VM1
    vm1->Ping(ip2);
    //vm2->Ping(ip1);

    this_thread::sleep_for (std::chrono::seconds(300));
    return 0;
}
