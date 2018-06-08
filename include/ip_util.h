#ifndef __IP_UTIL_H
#define __IP_UTIL_H

#include <string>
using namespace std;

#define IPV4_ALEN    4
#define IPV4_HDR_LEN sizeof(struct ipv4_hdr)

/*
 * 0       4       8               16                              32
 * +-------+-------+---------------+-------------------------------+
 * |Version|  IHL  |Type of Service|         Total Length          |
 * +-------------------------------+-+--+--+-----------------------+
 * |           Packet ID           | |DF|MF|    Fragment offset    |
 * +-------------------------------+-------------------------------+
 * | Time To Live  |  Protocol     |        Header Checksum        |
 * +---------------------------------------------------------------+
 * |                         Source Address                        |
 * +---------------------------------------------------------------+
 * |                       Destination Address                     |
 * +---------------------------------------------------------------+
 *
 */
struct ipv4_hdr {
    uint8_t  version_ihl;
#define IPV4_VERSION 4
#define IPV4_IHL     (IPV4_HDR_LEN / 4)
    uint8_t  type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
#define IP_FLAG_DF   0x4000 // Don't Fragment
    uint8_t  time_to_live;
    uint8_t  next_proto_id;
#define IP_P_ICMP    0x01
    uint16_t hdr_checksum;
    uint8_t  src_addr[IPV4_ALEN];
    uint8_t  dst_addr[IPV4_ALEN];
} __attribute__((__packed__));

class IpUtil {
    public:
        static void CreateIpV4Header(const string &src_ip, const string &dst_ip,
                                     uint16_t payload_len, struct ipv4_hdr *ipv4_hdr);
        static void IpStringToBytes(const string& ip, uint8_t *buf);
        static string IpBytesToString(const uint8_t *bytes);
        static uint16_t CalculateChecksum(const uint8_t *buf, uint32_t len);

};

#endif
