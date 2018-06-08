#include <vm.h>
#include <arp_util.h>
#include <ip_util.h>
#include <icmp_util.h>
#include <arpa/inet.h>
#include <iostream>

/**
 * Handle ingress ARP packet. For ARP request, reply if the target IP is itself.
 * For ARP reply, write to the ARP table and unblock the request.
 */
void VirtualMachine::HandleIngressArp() {
    struct arp_hdr arp_hdr;
    RecvFromNetwork((uint8_t *)&arp_hdr, sizeof(arp_hdr));
    struct arp_ipv4 arp_ipv4;
    RecvFromNetwork((uint8_t *)&arp_ipv4, sizeof(arp_ipv4));
    // From network byte order (big endian) to host byte order (little endian)
    arp_hdr.arp_op = ntohs(arp_hdr.arp_op);
    string src_mac = EthUtil::MacBytesToString(arp_ipv4.arp_sha);
    string src_ip = IpUtil::IpBytesToString(arp_ipv4.arp_sip);
    if (arp_hdr.arp_op == ARP_OP_REQUEST) {
        string dst_ip = IpUtil::IpBytesToString(arp_ipv4.arp_tip);
        cout << "[" << ip << "] Received ARP request: [Who has " << dst_ip
             << "? Tell " << src_ip << "]" << endl;
        if (ip == dst_ip) {
            cout << "[" << ip << "] Sending ARP reply: [" << dst_ip
                 << " is at " << mac << "]" << endl;
            SendArp(src_ip, src_mac, ARP_OP_REPLY);
        } else {
            cout << "[" << ip.size() << "] Ignore the ARP request " << dst_ip.size() << endl;
        }
    } else if (arp_hdr.arp_op == ARP_OP_REPLY) {
        unique_lock<mutex> arp_lock(arp_table_mutex);
        arp_table[src_ip] = src_mac;
        arp_cv.notify_one();
    } else {
        cout << "[" << ip << "] Received unsupported ARP type " << arp_hdr.arp_op << endl;
    }
}

/**
 * Handle ingress ICMP pakcet. For ICMP echo request, reply.
 * For ICMP echo reply, unblock the request.
 *
 * @param src_mac source MAC address
 */
void VirtualMachine::HandleIngressIcmp(const string &src_mac) {
    struct ipv4_hdr ip_hdr;
    RecvFromNetwork((uint8_t *)&ip_hdr, sizeof(ip_hdr));
    string dst_ip = IpUtil::IpBytesToString(ip_hdr.dst_addr);
    if (dst_ip != ip) {
        return;
    }
    string src_ip = IpUtil::IpBytesToString(ip_hdr.src_addr);
    struct icmp_hdr icmp_hdr;
    RecvFromNetwork((uint8_t *)&icmp_hdr, sizeof(icmp_hdr));
    struct icmp_echo icmp_echo;
    RecvFromNetwork((uint8_t *)&icmp_echo, sizeof(icmp_echo));
    uint16_t id = icmp_echo.id, seq_num = icmp_echo.seq_num;
    if (icmp_hdr.icmp_type == ICMP_ECHO_REQUEST) {
        cout << "[" << ip << "] Received ICMP request id = " << id
             << ", seq_num = " << seq_num<< endl;
        cout << "[" << ip << "] Sending ICMP reply id = " << id
             << ", seq_num = " << seq_num<< endl;
        SendIcmp(src_ip, src_mac, ICMP_ECHO_REPLY, id, seq_num);
    } else if (icmp_hdr.icmp_type == ICMP_ECHO_REPLY) {
        cout << "[" << ip << "] Received ICMP reply id = " << id
             << ", seq_num = " << seq_num<< endl;
        unique_lock<mutex> icmp_lock(icmp_reply_mutex);
        icmp_replies.insert({id, seq_num});
        icmp_cv.notify_one();
    } else {
        cout << "[" << ip << "] Received unsupported ICMP type "
             << icmp_hdr.icmp_type << endl;
    }
}

/**
 * Initialize the virtual machine. It starts a thread that handles ingress packets.
 */
void VirtualMachine::Init() {
    icmp_id = 1;
    icmp_seq = 1;
    // Right now we only support ingress ARP and ICMP packets
    auto loop = [&]() {
        cout << "VM [" << ip << ", " << mac << "] starts running." << endl;
        while (true) {
            struct eth_hdr eth_hdr;
            RecvFromNetwork((uint8_t *)&eth_hdr, sizeof(eth_hdr));
            string src_mac = EthUtil::MacBytesToString(eth_hdr.h_source);
            cout << "[" << ip << "] Received ethernet frame from " << src_mac << endl;
            eth_hdr.h_proto = ntohs(eth_hdr.h_proto);
            if (ETH_P_ARP == eth_hdr.h_proto) {
                HandleIngressArp();
            } else if (ETH_P_IP == eth_hdr.h_proto) {
                HandleIngressIcmp(src_mac);
            } else {
                cout << "[" << ip << "] Received unsupported ethernet type "
                     << eth_hdr.h_proto << endl;
            }
        }
    };
    ingress_proc_thread = thread(loop);
}

/**
 * De-initialize the virtual machine.
 */
void VirtualMachine::Deinit() {
    // TODO: Terminate the thread
}

/**
 * Send an ARP packet to the network.
 *
 * @param dst_ip[in]  destination IP address
 * @param dst_mac[in] destination MAC address
 * @param arp_op[in]  ARP_OP_REQUEST or ARP_OP_REPLY
 */
void VirtualMachine::SendArp(const string& dst_ip, const string &dst_mac,
                             uint16_t arp_op) {
    uint8_t buf[ETH_HDR_LEN + ARP_HDR_LEN + ARP_IPV4_LEN] = {0};
    // Ethernet header
    struct eth_hdr *eth_hdr = (struct eth_hdr *) buf;
    EthUtil::CreateEtherHeader(mac, dst_mac, ETH_P_ARP, eth_hdr);

    // ARP Header
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(eth_hdr + 1);
    ArpUtil::CreateArpHeader(arp_op, arp_hdr);

    // ARP Body
    struct arp_ipv4 *arp_ipv4 = (struct arp_ipv4 *)(arp_hdr + 1);
    ArpUtil::CreateArpBody(mac, ip, dst_mac, dst_ip, arp_ipv4);
    SendToNetwork(buf, sizeof(buf));
}

/**
 * Send an ICMP packet to the network.
 *
 * @param dst_ip[in]    destination IP address
 * @param dst_mac[in]   destination MAC address
 * @param icmp_type[in] ICMP_ECHO_REQUEST or ICMP_ECHO_REPLY
 * @param id[in]        id of the echo packet
 * @param seq_num[in]   sequence number of the echo packet
 */
void VirtualMachine::SendIcmp(const string &dst_ip, const string &dst_mac,
                              uint8_t icmp_type, uint16_t id, uint16_t seq_num) {
    uint8_t buf[ETH_HDR_LEN + IPV4_HDR_LEN + ICMP_HDR_LEN + ICMP_ECHO_LEN];
    // Ethernet header
    struct eth_hdr *eth_hdr = (struct eth_hdr *) buf;
    EthUtil::CreateEtherHeader(mac, dst_mac, ETH_P_IP, eth_hdr);

    // IPV4 header
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    IpUtil::CreateIpV4Header(ip, dst_ip, ICMP_HDR_LEN + ICMP_ECHO_LEN, ipv4_hdr);

    // ICMP header
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(ipv4_hdr + 1);
    IcmpUtil::CreateIcmpEcho(icmp_type, icmp_hdr, id, seq_num);

    SendToNetwork(buf, sizeof(buf));
}

/**
 * Ping an IP address.
 *
 * @param dst_ip[in] the IP address to ping
 */
void VirtualMachine::Ping(const string &dst_ip) {
    unique_lock<mutex> arp_lock(arp_table_mutex);
    if (arp_table.find(dst_ip) == arp_table.end()) {
        cout << "[" << ip << "] Sending ARP request to "
             << dst_ip << "..." << endl;
        SendArp(dst_ip, kEthBroadcastAddr, ARP_OP_REQUEST);
        cout << "[" << ip << "] Waiting for ARP reply from "
             << dst_ip << "..." << endl;
        arp_cv.wait(arp_lock, [&]{ return arp_table.find(dst_ip) != arp_table.end(); });
    }

    string dst_mac = arp_table[dst_ip];
    uint16_t id = icmp_id++, seq_num = icmp_seq++;
    pair<uint16_t, uint16_t> key = make_pair(id, seq_num);

    cout << "[" << ip << "] Ping " << dst_ip << " ..." << endl;
    auto start = chrono::steady_clock::now();

    SendIcmp(dst_ip, dst_mac, ICMP_ECHO_REQUEST, id, seq_num);
    unique_lock<mutex> icmp_lock(icmp_reply_mutex);
    icmp_cv.wait(icmp_lock, [&]{ return icmp_replies.find(key) != icmp_replies.end();});

    auto end = chrono::steady_clock::now();
    auto diff = end - start;
    cout << "[" << ip << "] Ping response from " << ip << ": icmp_seq=" << seq_num;
    cout << " time=" << chrono::duration <double, milli> (diff).count() << " ms" << endl;

    icmp_replies.erase(key);
}

/**
 * Send bytes from the VM to network.
 *
 * @param[in] buf the byte buffer to send
 * @param[in] len length of the buffer
 */
void VirtualMachine::SendToNetwork(const uint8_t *buf, size_t len) {
    write(tap_fd, buf, len);
}

/**
 * Receive bytes from the network. This is a blocking call.
 *
 * @param[out] buf the buffer to receive bytes
 * @param[in] len length of bytes to receive
 */
void VirtualMachine::RecvFromNetwork(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unique_lock<mutex> lock(ingress_queue_mutex);
        ingress_cv.wait(lock, [&]{ return !ingress_queue.empty(); });
        buf[i] = ingress_queue.front();
        ingress_queue.pop();
    }
}

/**
 * Send bytes from network to the VM.
 *
 * @param[in] buf the byte buffer
 * @param[in] len length of the buffer
 */
void VirtualMachine::SendToVm(const uint8_t *buf, size_t len) {
    unique_lock<mutex> lock(ingress_queue_mutex);
    for (size_t i = 0; i < len; i++) {
        ingress_queue.push(buf[i]);
    }
    ingress_cv.notify_one();
}
