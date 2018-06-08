#include <sstream>
#include <arpa/inet.h>
#include <eth_util.h>

/*
 * Creater an ethernet header. The result is in network byte order
 *
 * @param[in]  src_mac source MAC address
 * @param[in]  dst_mac destination MAC address
 * @param[in]  ether_type ethernet type such as ETH_P_ARP or ETH_P_IP
 * @param[out] buf the ethernet header in network byte order
 */
void EthUtil::CreateEtherHeader(const string &src_mac, const string &dst_mac,
                                uint16_t ether_type, struct eth_hdr *eth_hdr) {
    MacStringToBytes(src_mac, eth_hdr->h_source);
    MacStringToBytes(dst_mac, eth_hdr->h_dest);
    eth_hdr->h_proto = htons(ether_type);
}


/**
 * Convert a MAC address string to a byte array.
 * The result is in network byte order (big endian).
 *
 * @param[in]  mac mac address in format like "01:23:45:67:89"
 * @param[out] buf the conversion result
 */
void EthUtil::MacStringToBytes(const string& mac, uint8_t *buf) {
    stringstream ss(mac);
    string token;

	uint8_t *p = buf;
    while (getline(ss, token, ':')) {
        *(p++) = stoi(token, nullptr, 16);
    }
}

/**
 * Convert a MAC address byte array to string.
 *
 * @param bytes[in] the MAC address byte array in network byte order
 * @return the converted MAC address string
 */
string EthUtil::MacBytesToString(const uint8_t *bytes) {
    string mac;
    const static char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int i = 0; i < ETH_ALEN; i++) {
        mac += hexmap[(bytes[i] & 0xF0) >> 4];
        mac += hexmap[bytes[i] & 0x0F];
        mac += ':';
    }
    mac.pop_back(); // Pop last ':'
    return mac;
}
