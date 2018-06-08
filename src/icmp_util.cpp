#include <arpa/inet.h>
#include <icmp_util.h>
#include <ip_util.h>

/**
 * Create an ICMP echo packet.
 *
 * @param type[in]      ICMP_ECHO_REQUEST or ICMP_ECHO_REPLY
 * @param icmp_hdr[out] the ICMP header
 * @param id[in]        id of the echo pakcet
 * @param seq_num[in]   sequence numbe of the echo packet
 */
void IcmpUtil::CreateIcmpEcho(uint8_t type, struct icmp_hdr *icmp_hdr,
                              uint16_t id, uint16_t seq_num) {
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_checksum = 0;

    struct icmp_echo *icmp_echo = (struct icmp_echo *)(icmp_hdr + 1);
    icmp_echo->id = id;
    icmp_echo->seq_num = seq_num;

    uint16_t checksum = IpUtil::CalculateChecksum(
            (uint8_t *)icmp_hdr, ICMP_HDR_LEN + ICMP_ECHO_LEN);
    icmp_hdr->icmp_checksum = htons(checksum);
}
