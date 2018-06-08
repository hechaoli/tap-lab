#ifndef __ETH_UTIL_H
#define __ETH_UTIL_H

#include <string>
#include <stdint.h>
using namespace std;

#define ETH_ALEN  6

/**
 * Ethernet Header
 *
 * 0                 48                96          112
 * +-----------------+-----------------+------------+
 * | MAC Destination |    MAC Source   | Ether Type |
 * +-----------------+-----------------+------------+
 */
struct eth_hdr {
    uint8_t  h_dest[ETH_ALEN];
    uint8_t  h_source[ETH_ALEN];
    uint16_t h_proto;
#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800
} __attribute__((packed));

#define ETH_HDR_LEN sizeof(struct eth_hdr)

const string kEthBroadcastAddr = "FF:FF:FF:FF:FF:FF";

class EthUtil {
    public:
        static void CreateEtherHeader(const string &src_mac, const string &dst_maca,
                                      uint16_t ether_type, struct eth_hdr *eth_hdr);
        static void MacStringToBytes(const string &mac, uint8_t *buf);
        static string MacBytesToString(const uint8_t *bytes);
};

#endif
