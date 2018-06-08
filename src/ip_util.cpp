#include <sstream>
#include <ip_util.h>
#include <arpa/inet.h>


/**
 * Create an IPV4 header. The result is in network byte order.
 *
 * @param[in] src_ip source IP address
 * @param[in] dst_ip destination IP address
 * @param[in] payload_len length of the IP payload
 */
void IpUtil::CreateIpV4Header(const string &src_ip, const string &dst_ip,
                              uint16_t payload_len, struct ipv4_hdr *ipv4_hdr) {
    ipv4_hdr->version_ihl = (IPV4_VERSION << 4) | IPV4_IHL;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = htons(sizeof(struct ipv4_hdr) + payload_len);
    ipv4_hdr->packet_id = 0;
    ipv4_hdr->fragment_offset = htons(IP_FLAG_DF);
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IP_P_ICMP;
    ipv4_hdr->hdr_checksum = 0;
    IpStringToBytes(src_ip, ipv4_hdr->src_addr);
    IpStringToBytes(dst_ip, ipv4_hdr->dst_addr);
    uint16_t checksum = CalculateChecksum((uint8_t *) ipv4_hdr, IPV4_HDR_LEN);
    ipv4_hdr->hdr_checksum = htons(checksum);
}

/**
 * Convert a IP string to byte array.
 *
 * @param ip[in]     the IP string
 * @param bytes[out] the byte array converted from ip
 */
void IpUtil::IpStringToBytes(const string &ip, uint8_t *bytes) {
    stringstream ss(ip);
    string token;
    uint8_t *p = bytes;
    while (getline(ss, token, '.')) {
        *(p++) = stoi(token);
    }
}

/**
 * Convert an IP byte array to string.
 *
 * @param bytes[in] the IP byte array in network byte order
 */
string IpUtil::IpBytesToString(const uint8_t *bytes) {
    string ip;
    for (int i = 0; i < IPV4_ALEN; i++) {
        ip += to_string(bytes[i]) + ".";
    }
    ip.pop_back(); // Pop the last '.'
    return ip;
}

/**
 * Calculate the checksum. See https://en.wikipedia.org/wiki/IPv4_header_checksum
 *
 * @param buf[in] the byte array to calculate the checksum in network byte order
 * @param len[in] length of the byte array
 * @return the checksum of the byte array
 */
uint16_t IpUtil::CalculateChecksum(const uint8_t *buf, uint32_t len) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < len; i += 2) {
       sum += ((buf[i] << 8) & 0xFF00) + (buf[i + 1] & 0x00FF);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}
