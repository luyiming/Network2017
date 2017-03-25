#include <arpa/inet.h>       // inet_addr, inet_ntoa, ntohs etc
#include <linux/if_ether.h>  // ETH_P_ALL
#include <netinet/in.h>      // ntohs(), htonl()...
#include <stdio.h>           // printf()
#include <string.h>          // strlen(), strtok()
#include <sys/socket.h>      // socket()
#include <unistd.h>          // getpid()
#include "dns.h"             // dns data type && functions
#include "type.h"            // data strcuture definition
#include "util.h"            // utilities

#define BUFFER_MAX 2048

extern void unpack_dns_packet(unsigned char *buf);

void unpack_http_packet(unsigned char *buf);
void unpack_tcp_packet(unsigned char *buf);
void unpack_udp_packet(unsigned char *buf);
void unpack_icmp_packet(unsigned char *buf);
void unpack_ip_packet(struct IPPack *packet);
void unpack_arp_packet(struct EthArpPack *packet_arp);
void unpack_eth_packet(unsigned char *buf);

int filter_packet(unsigned char *buf);

struct globalArgs_t {
    int b_tcp;
    int b_udp;
    int b_dns;
    int b_http;
    int b_arp;
    int b_icmp;
    int b_all;
    unsigned int count;
} globalArgs;
static const char *optString = "c:t:a";
void parse_opt(int argc, char **argv);

/**
 * input options:
 * -a : sniff all packets
 * -c [count] : Exit after receiving count packets.
 * -t [tcp/udp/icmp/arp/dns/http] : sniff specified type of packets
 */
int main(int argc, char *argv[]) {
    parse_opt(argc, argv);

    int packets_count = 0;
    int sock_fd;
    int n_read;
    unsigned char buffer[BUFFER_MAX];
    if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("error create raw socket\n");
        return -1;
    }
    while (1) {
        // memset(buffer,0,BUFFER_MAX);
        n_read = recvfrom(sock_fd, buffer, 2048, 0, NULL, NULL);
        if (n_read < 42) {
            printf("error when recv msg \n");
            return -1;
        }
        if (filter_packet(buffer) && packets_count < globalArgs.count) {
            printf("--------------------------------------------------------> packets count #%d\n",
                   packets_count);
            unpack_eth_packet(buffer);
            packets_count++;
        }
        if (packets_count == globalArgs.count) return 0;
    }
    return 0;
}

/**
 * parse command options
 * @method parse_opt
 * @param  argc      [main argc]
 * @param  argv      [main argv]
 */
void parse_opt(int argc, char **argv) {
    globalArgs.b_tcp = globalArgs.b_udp = globalArgs.b_dns = globalArgs.b_http =
        globalArgs.b_arp = globalArgs.b_icmp = globalArgs.b_all = 0;
    globalArgs.count = -1;
    int opt = getopt(argc, argv, optString);
    while (opt != -1) {
        switch (opt) {
            case 'c':
                globalArgs.count = atoi(optarg);
                break;
            case 'a':
                globalArgs.b_all = 1;
                break;
            case 't':
                if (strcmp(optarg, "tcp") == 0) globalArgs.b_tcp = 1;
                if (strcmp(optarg, "udp") == 0) globalArgs.b_udp = 1;
                if (strcmp(optarg, "dns") == 0) globalArgs.b_dns = 1;
                if (strcmp(optarg, "http") == 0) globalArgs.b_http = 1;
                if (strcmp(optarg, "arp") == 0) globalArgs.b_arp = 1;
                if (strcmp(optarg, "icmp") == 0) globalArgs.b_icmp = 1;
                break;
            default:
                /* You won't actually get here. */
                break;
        }
        opt = getopt(argc, argv, optString);
    }
}

/**
 * filter packets to be processed
 * @method filter_packet
 * @param  buf           [incomming packet]
 * @return               [1 if to be processed, 0 if filtered]
 */
int filter_packet(unsigned char *buf) {
    if (globalArgs.b_all == 1) {
        return 1;
    }
    struct EthPack *packet = (struct EthPack *)buf;
    // IP
    if (htons(packet->type) == 0x0800) {
        struct IPPack *ippacket = &packet->ipPack;
        if (ippacket->protocol == IPPROTO_ICMP) {
            if (globalArgs.b_icmp == 1)
                return 1;
            else
                return 0;
        } else if (ippacket->protocol == IPPROTO_TCP) {
            if (globalArgs.b_tcp == 1)
                return 1;
            else {
                struct TCPPack *tcppacket = (struct TCPPack *)ippacket->payload;
                // HTTP
                if (ntohs(tcppacket->srcPort) == 80 ||
                    ntohs(tcppacket->dstPort) == 80) {
                    if (globalArgs.b_http == 1)
                        return 1;
                    else
                        return 0;
                } else
                    return 0;
            }
        } else if (ippacket->protocol == IPPROTO_UDP) {
            if (globalArgs.b_udp == 1)
                return 1;
            else {
                struct UDPPack *udppacket = (struct UDPPack *)ippacket->payload;
                // DNS
                if (ntohs(udppacket->srcPort) == 53 ||
                    ntohs(udppacket->dstPort) == 53) {
                    if (globalArgs.b_dns == 1)
                        return 1;
                    else
                        return 0;
                } else
                    return 0;
            }
        } else
            return 0;
    }
    // ARP
    if (htons(packet->type) == 0x0806) {
        if (globalArgs.b_arp == 1)
            return 1;
        else
            return 0;
    }
    return 0;
}

void unpack_http_packet(unsigned char *buf) {
    PRINT_Light_Red(" HTTP Header:\n");
}


void unpack_tcp_packet(unsigned char *buf) {
    PRINT_Light_Green(" TCP Header:\n");

    struct TCPPack *packet = (struct TCPPack *)buf;
    printf("Port\t\t: %d ==> %d\n", ntohs(packet->srcPort),
           ntohs(packet->dstPort));

    printf("Sequence number\t: %u\n", ntohl(packet->sequence));
    printf("Ack number\t: %d\n", ntohl(packet->ack));

    printf("Header length\t: %d\n", packet->offset * 4);

    uint16_t flags = ntohs(packet->flags);
    printf("Flags\t\t: 0x%03x ", flags & 0xfff);
    printf("(");
    if (flags & URGENT_BIT) printf("URGENT ");
    if (flags & ACK_BIT) printf("ACK ");
    if (flags & PUSH_BIT) printf("PSH ");
    if (flags & RESET_BIT) printf("RST ");
    if (flags & SYN_BIT) printf("SYN ");
    if (flags & FIN_BIT) printf("FIN ");
    printf(")\n");

    printf("Window size\t: %d\n", ntohs(packet->windowSize));

    printf("Checksum\t: 0x%04x\n", ntohs(packet->checksum));
    printf("Urgent pointer\t: %d\n", ntohs(packet->urgentPointer));

    switch (ntohs(packet->dstPort)) {
        case 80:
            unpack_http_packet(&packet->payload);
            break;
    }
}

void unpack_udp_packet(unsigned char *buf) {
    PRINT_Light_Green(" UDP Header:\n");

    struct UDPPack *packet = (struct UDPPack *)buf;
    printf("Port\t\t: %d ==> %d\n", ntohs(packet->srcPort),
           ntohs(packet->dstPort));

    printf("Length\t\t: %d\n", ntohs(packet->length));

    printf("Checksum\t: 0x%04x\n", ntohs(packet->checksum));

    switch (ntohs(packet->srcPort)) {
        case 53:
            unpack_dns_packet(&packet->payload);
            break;
    }
    switch (ntohs(packet->dstPort)) {
        case 53:
            unpack_dns_packet(&packet->payload);
            break;
    }
}

void unpack_icmp_packet(unsigned char *buf) {
    PRINT_Light_Green(" ICMP Header:\n");

    struct ICMPPack *packet = (struct ICMPPack *)buf;

    printf("Type\t\t: %d ", packet->type);
    switch (packet->type) {
        case ICMP_ECHOREPLY:
            printf("Echo (ping) Reply\n");
            break;
        case ICMP_DEST_UNREACH:
            printf("Destination Unreachable\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf("Source Quench\n");
            break;
        case ICMP_REDIRECT:
            printf("Redirect (change route)\n");
            break;
        case ICMP_ECHO:
            printf("Echo (ping) Request\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("Time Exceeded\n");
            break;
        case ICMP_PARAMETERPROB:
            printf("Parameter Problem\n");
            break;
        case ICMP_TIMESTAMP:
            printf("Timestamp Request\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("Timestamp Reply\n");
            break;
        case ICMP_INFO_REQUEST:
            printf("Information Request\n");
            break;
        case ICMP_INFO_REPLY:
            printf("Information Reply\n");
            break;
        case ICMP_ADDRESS:
            printf("Address Mask Request\n");
            break;
        case ICMP_ADDRESSREPLY:
            printf("Address Mask Reply\n");
            break;
        default:
            printf("Unknown Type\n");
            break;
    }

    printf("Code\t\t: %d ", packet->code);
    if (packet->type == ICMP_DEST_UNREACH) {
        switch (packet->code) {
            case ICMP_NET_UNREACH:
                printf("Network Unreachable\n");
                break;
            case ICMP_HOST_UNREACH:
                printf("Host Unreachable\n");
                break;
            case ICMP_PROT_UNREACH:
                printf("Protocol Unreachable\n");
                break;
            case ICMP_PORT_UNREACH:
                printf("Port Unreachable\n");
                break;
            case ICMP_FRAG_NEEDED:
                printf("Fragmentation Needed/DF set\n");
                break;
            case ICMP_SR_FAILED:
                printf("Source Route failed\n");
                break;
            case ICMP_NET_UNKNOWN:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_HOST_UNKNOWN:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_HOST_ISOLATED:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_NET_ANO:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_HOST_ANO:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_NET_UNR_TOS:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_HOST_UNR_TOS:
                printf("ICMP_NET_UNKNOWN \n");
                break;
            case ICMP_PKT_FILTERED:
                printf("Packet filtered \n");
                break;
            case ICMP_PREC_VIOLATION:
                printf("Precedence violation \n");
                break;
            case ICMP_PREC_CUTOFF:
                printf("Precedence cut off \n");
                break;
            default:
                printf("Unknown code\n");
                break;
        }
    } else if (packet->type == ICMP_REDIRECT) {
        switch (packet->code) {
            case ICMP_REDIR_NET:
                printf("Redirect Net\n");
                break;
            case ICMP_REDIR_HOST:
                printf("Redirect Host\n");
                break;
            case ICMP_REDIR_NETTOS:
                printf("Redirect Net for TOS\n");
                break;
            case ICMP_REDIR_HOSTTOS:
                printf("Redirect Host for TOS\n");
                break;
            default:
                printf("Unknown code\n");
                break;
        }
    } else if (packet->type == ICMP_TIME_EXCEEDED) {
        switch (packet->code) {
            case ICMP_EXC_TTL:
                printf("TTL count exceeded\n");
                break;
            case ICMP_EXC_FRAGTIME:
                printf("Fragment Reass time exceeded\n");
                break;
            default:
                printf("Unknown code\n");
                break;
        }
    } else {
        printf("\n");
    }

    printf("Checksum\t: 0x%04x\n", ntohs(packet->checksum));

    int len = 56;
    if (packet->code == ICMP_ECHO || packet->code == ICMP_ECHOREPLY) {
        printf("Identifier (BE)\t: %d (0x%04x)\n", ntohs(packet->un.echo.id),
               ntohs(packet->un.echo.id));
        printf("Identifier (LE)\t: %d (0x%04x)\n", packet->un.echo.id,
               packet->un.echo.id);

        printf("Seq Number (BE)\t: %d (0x%04x)\n",
               ntohs(packet->un.echo.sequence),
               ntohs(packet->un.echo.sequence));
        printf("Seq Number (LE)\t: %d (0x%04x)\n", packet->un.echo.sequence,
               packet->un.echo.sequence);
    }

    printf("Data\t\t: (%d bytes)\n", len);
    for (int i = 0; i < len; i++) {
        printf("0x%x ", packet->data[i]);
    }
    printf("\n");
}

void unpack_ip_packet(struct IPPack *packet) {
    PRINT_Light_Cyan(" IP Header:\n");

    printf("version\t\t: ");
    printf("%02x ", packet->version);
    if ((packet->version) == 0x4)
        printf("(IPv4)\n");
    else if ((packet->version) == 0x6)
        printf("(IPv6)\n");

    printf("header length\t: %d bytes\n", packet->header_length * 4);

    printf("total length\t: %d bytes\n", ntohs(packet->length));

    printf("Identification\t: 0x%04x\n", ntohs(packet->id));

    printf("TTL\t\t: %d\n", packet->TTL);

    unsigned char *p = (unsigned char *)packet->srcIP;
    printf("IP\t\t: %d.%d.%d.%d ==> %d.%d.%d.%d\n", p[0], p[1], p[2], p[3],
           p[4], p[5], p[6], p[7]);

    printf("Protocol\t: ");
    switch (packet->protocol) {
        case IPPROTO_ICMP:
            printf("ICMP (%d)\n", packet->protocol);
            unpack_icmp_packet(packet->payload);
            break;
        case IPPROTO_IGMP:
            printf("IGMP (%d)\n", packet->protocol);
            break;
        case IPPROTO_IPIP:
            printf("TPTP (%d)\n", packet->protocol);
            break;
        case IPPROTO_TCP:
            printf("TCP (%d)\n", packet->protocol);
            unpack_tcp_packet(packet->payload);
            break;
        case IPPROTO_UDP:
            printf("UDP (%d)\n", packet->protocol);
            unpack_udp_packet(packet->payload);
            break;
        default:
            printf("others (%d)\n", packet->protocol);
    }
}

void unpack_arp_packet(struct EthArpPack *packet_arp) {
    PRINT_Light_Cyan(" ARP Header:\n");

    if ((packet_arp->protocol[0] == 0x08) && (packet_arp->protocol[1] == 0x00))
        printf("ARP_IP\n");
    switch (packet_arp->opcode[1]) {
        case 0x01:
            printf("ARP request\n");
            break;
        case 0x02:
            printf("ARP response\n");
            break;
        case 0x03:
            printf("RARP\n");
            break;
    }
    printf("source mac addr\t:");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", packet_arp->srcHrdAddr[i]);
    }
    printf("\nsource ip addr\t:");
    for (int i = 0; i < 4; i++) {
        printf("%d ", packet_arp->srcIPAddr[i]);
    }
    printf("\ndestination mac addr\t:");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", packet_arp->dstHrdAddr[i]);
    }
    printf("\ndestination IP addr\t:");
    for (int i = 0; i < 4; i++) {
        printf("%d ", packet_arp->dstIPAddr[i]);
    }
    printf("\n");
}

void unpack_eth_packet(unsigned char *buf) {
    PRINT_Light_Cyan(" Ethernet Header:\n");
    struct EthPack *packet = (struct EthPack *)buf;
    unsigned char *p = buf;
    printf(
        "MAC address\t: %.2x:%02x:%02x:%02x:%02x:%02x ==> "
        "%.2x:%02x:%02x:%02x:%02x:%02x\n",
        p[6], p[7], p[8], p[9], p[10], p[11], p[0], p[1], p[2], p[3], p[4],
        p[5]);

    printf("type\t\t: 0x%04x ", ntohs(packet->type));
    if (htons(packet->type) == 0x0800) {
        printf("(IP)\n");
        unpack_ip_packet(&packet->ipPack);
    }
    if (htons(packet->type) == 0x0806) {
        printf("(ARP)\n");
        unpack_arp_packet((struct EthArpPack *)buf);
    }
}
