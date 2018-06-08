#include <arpa/inet.h> // For htons
#include <arp_util.h>

/**
 * Create an ARP header for IP protocol.
 * The result is in network byte order.
 *
 * @param[in]  arp_op ARP op code
 * @param[out] arp_hdr the result ARP header
 */
void ArpUtil::CreateArpHeader(uint16_t arp_op, struct arp_hdr *arp_hdr) {
    arp_hdr->arp_hrd = htons(ARP_HRD_ETHER);
    arp_hdr->arp_pro = htons(ETH_P_IP);
    arp_hdr->arp_hln = ETH_ALEN;
    arp_hdr->arp_pln = IPV4_ALEN;
    arp_hdr->arp_op = htons(arp_op);
}

/**
 * Create an ARP packet body with protocol being IPV4.
 * The result is in network byte order.
 *
 * @param[in]  sha sender hardware address
 * @param[in]  sip sender IP address
 * @param[in]  tha target hardware address
 * @param[in]  tip target IP address
 * @param[out] arp_ipv4 the result ARP body
 */
void ArpUtil::CreateArpBody(const string& sha, const string& sip,
                            const string& tha, const string& tip,
                            struct arp_ipv4 *arp_ipv4) {
	// Sender Hardware Address
    EthUtil::MacStringToBytes(sha, arp_ipv4->arp_sha);
	// Sender IP Address
    IpUtil::IpStringToBytes(sip, arp_ipv4->arp_sip);
	// Target Hardware Address
    EthUtil::MacStringToBytes(tha, arp_ipv4->arp_tha);
	// Target IP Address
    IpUtil::IpStringToBytes(tip, arp_ipv4->arp_tip);
}
