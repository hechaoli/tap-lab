#include <hypervisor.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> // For open()
#include <cstring> // For memset()
#include <net/if.h> // For ifreq
#include <sys/ioctl.h> // For ioctl
#include <unistd.h> // For close()
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * Get the file descriptor of a TAP interface.
 * If the TAP of given name does not exist, it will be created.
 *
 * @param name[in] name of the TAP interface
 * @return file descriptor of the TAP interface
 */
static int GetTapFd(const string &name) {
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Failed to open /dev/net/tun");
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // Don't provide packet information
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (!name.empty()) {
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    }

    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(fd);
        perror("Failed to create TAP interface");
        return err;
    }
    return fd;
}

/**
 * Build the file descriptor set for select().
 * It will set the file descriptor of all existing VMs.
 *
 * @param fds[in] the fd_set struct to set
 */
void Hypervisor::BuildFdSet(fd_set *fds) {
    lock_guard<std::mutex> lock(vm_map_mutex);
    FD_ZERO(fds);
    for (auto &kv : vm_map) {
        int fd = kv.first;
        FD_SET(fd, fds);
    }
}

/**
 * Read data from file descriptors and dispatch it to the VMs.
 *
 * @param fds[in] the fd_set that contains all file descriptors to read from
 */
void Hypervisor::HandleRead(fd_set *fds) {
    lock_guard<std::mutex> lock(vm_map_mutex);
    for (auto &kv : vm_map) {
        int fd = kv.first;
        if (FD_ISSET(fd, fds)) {
            VirtualMachine *vm = kv.second;
            uint8_t buf[BUF_SIZE];
            int len = read(fd, buf, sizeof(buf));
            vm->SendToVm(buf, len);
        }
    }
}

/**
 * Initialize the hypervisor.
 */
void Hypervisor::Init() {
    max_fd = -1;
    next_vm_id = 0;
    auto loop = [&]() {
        while (true) {
            fd_set fds;
            BuildFdSet(&fds);
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            int ret = select(max_fd + 1, &fds, NULL, NULL, &timeout);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("select()");
                return;
            } else if (ret == 0) {
                continue;
            }
            HandleRead(&fds);
        }
    };

    select_thread = thread(loop);
}

/**
 * Create a virtual machine.
 *
 * @param mac[in] MAC address of the VM
 * @param ip[in]  IP address of the VM
 * @return pointer to the newly created VM
 */
VirtualMachine *Hypervisor::createVM(const string &mac, const string &ip) {
    int vm_id = next_vm_id++;
    string tap_name = "tap" + to_string(vm_id);
    int tap_fd = GetTapFd(tap_name);

    VirtualMachine *vm = new VirtualMachine(mac, ip, tap_fd);
    lock_guard<std::mutex> lock(vm_map_mutex);
    vm_map[tap_fd] = vm;
    max_fd = max(max_fd.load(), tap_fd);
    return vm;
}

