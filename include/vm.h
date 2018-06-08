#ifndef __VM_H
#define __VM_H

#include <string>
#include <unordered_map>
#include <set>
#include <utility>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <unistd.h>

using namespace std;

class VirtualMachine {
    private:
        string mac;
        string ip;
        int tap_fd;
        uint16_t icmp_id, icmp_seq;

        unordered_map<string, string> arp_table;
        set<pair<uint16_t, uint16_t>> icmp_replies;
        queue<uint8_t> ingress_queue;

        mutex ingress_queue_mutex;
        mutex arp_table_mutex;
        mutex icmp_reply_mutex;

        condition_variable ingress_cv;
        condition_variable arp_cv;
        condition_variable icmp_cv;

        thread ingress_proc_thread;

        void Init();
        void Deinit();
        void SendArp(const string &dst_ip, const string &dst_mac, uint16_t arp_op);
        void SendIcmp(const string &dst_ip, const string &dst_mac,
                      uint8_t type, uint16_t id, uint16_t seq_num);
        void SendToNetwork(const uint8_t *buf, size_t len);
        void RecvFromNetwork(uint8_t *buf, size_t len);
        void HandleIngressArp();
        void HandleIngressIcmp(const string &src_mac);
    public:
        VirtualMachine(string mac, string ip, int tap_fd)
            : mac(mac), ip(ip), tap_fd(tap_fd) { Init(); }
        ~VirtualMachine() { Deinit(); }
        void ping(const string& ip);
        void SendToVm(const uint8_t *buf, size_t len);
};

#endif
