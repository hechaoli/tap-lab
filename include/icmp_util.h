#ifndef __ICMP_H
#define __ICMP_H

#include <cstdint>

#define ICMP_HDR_LEN      sizeof(struct icmp_hdr)
#define ICMP_ECHO_LEN     sizeof(struct icmp_echo)

/*
 * 0        8       16                32
 * +--------+--------+----------------+
 * |  Type  |  Code  |    Checksum    |
 * +--------+--------+----------------+
 *
 */
struct icmp_hdr {
    uint8_t  icmp_type;
#define ICMP_ECHO_REQUEST 0x08
#define ICMP_ECHO_REPLY   0x00
    uint8_t  icmp_code;
    uint16_t icmp_checksum;
} __attribute__((packed));

/*
 * 0        8       16                32
 * +-----------------+----------------+
 * |    Identifier   |Sequence Number |
 * +-----------------+----------------+
 * |       Data (Variable Length)     |
 * +-----------------+----------------+
 *
 */
struct icmp_echo {
    uint16_t id;
    uint16_t seq_num;
    uint8_t  data[];
} __attribute__((packed));

class IcmpUtil {
    public:
        static void CreateIcmpEcho(uint8_t type, struct icmp_hdr *icmp_hdr,
                                   uint16_t id, uint16_t seq_num);
};

#endif
