#ifndef __ARP_H
#define __ARP_H

#include <cstring>
#include "eth_util.h"
#include "ip_util.h"

using namespace std;

/**
 * ARP Format
 *
 * 0                                    16                                     32
 * +-------------------------------------+-------------------------------------+
 * |       Hardware Type                 |             Protocol Type           |
 * +------------------+------------------+-------------------------------------+
 * | Hardware Address | Protocol Address |               Opcode                |
 * |       Length     |       Length     |                                     |
 * +------------------+------------------+-------------------------------------+
 * |       Sender Hardware Address                                             |
 * +              (6 bytes)              +-------------------------------------+
 * |                                     |  Sender Protocol Address (byte 1-2) |
 * +------------------+------------------+-------------------------------------+
 * |  Sender Protocol Address (byte 3-4) |        Target Hardware Address      |
 * +-------------------------------------+               (6 bytes)             +
 * |                                                                           |
 * +-------------------------------------+-------------------------------------+
 * |                        Target Protocol Address                            |
 * +-------------------------------------+-------------------------------------+
 */
struct arp_hdr {
    uint16_t arp_hrd;         /* format of hardware address   */
#define ARP_HRD_ETHER     1   /* ARP Ethernet address format */
    uint16_t arp_pro;         /* format of protocol address   */
    uint8_t  arp_hln;         /* length of hardware address   */
    uint8_t  arp_pln;         /* length of protocol address   */
    uint16_t arp_op;          /* ARP opcode (command)     */
#define ARP_OP_REQUEST    1   /* request to resolve address */
#define ARP_OP_REPLY      2   /* response to previous request */
#define ARP_OP_REVREQUEST 3   /* request proto addr given hardware */
#define ARP_OP_REVREPLY   4   /* response giving protocol address */
#define ARP_OP_INVREQUEST 8   /* request to identify peer */
#define ARP_OP_INVREPLY   9   /* response identifying peer */
} __attribute__((__packed__));

struct arp_ipv4 {
    uint8_t arp_sha[ETH_ALEN];  /* Sender Hardware Address */
    uint8_t arp_sip[IPV4_ALEN]; /* Sender IP Address */
    uint8_t arp_tha[ETH_ALEN];  /* Target Hardware Address */
    uint8_t arp_tip[IPV4_ALEN]; /* Target IP Address */
} __attribute__((__packed__));

#define ARP_HDR_LEN sizeof(struct arp_hdr)
#define ARP_IPV4_LEN sizeof(struct arp_ipv4)

class ArpUtil {
    public:
        static void CreateArpHeader(uint16_t arp_op, struct arp_hdr *arp_hdr);
        static void CreateArpBody(const string& sha, const string& sip,
                                  const string& tha, const string& tip,
                                  struct arp_ipv4 *arp_ipv4);
};

#endif
