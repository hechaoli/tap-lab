#ifndef __HYPERVISOR_H
#define __HYPERVISOR_H

#include <string>
#include <mutex>
#include <thread>
#include <vm.h>
#include <atomic>

#define BUF_SIZE 2000

using namespace std;
class Hypervisor {
    private:
        unordered_map<int, VirtualMachine *> vm_map; // Map from tap fd to VM
        mutex vm_map_mutex;

        atomic<int> max_fd;
        atomic<int> next_vm_id;
        thread select_thread;

		void BuildFdSet(fd_set *fds);
		void HandleRead(fd_set *fds);
        void Init();
    public:
        Hypervisor() { Init(); }
        VirtualMachine *createVM(const string& mac, const string& ip);
        void removeVM(int vm_id); // TODO: Implement
};

#endif
