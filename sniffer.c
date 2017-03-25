#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <linux/if_ether.h>
#include <netinet/in.h>  // ntohs ...
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "type.h"

#define BUFFER_MAX 2048

void unpack_http_packet(unsigned char *buf) {}

unsigned char *readDNSName(unsigned char *reader, unsigned char *buffer, int *count) {
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reader != 0) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) -
                     49152;  // 49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1;
        } else {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0) {
            *count = *count + 1;  // if we havent jumped to another location
                                  // then we can count up
        }
    }

    name[p] = '\0';
    if (jumped == 1) {
        *count = *count + 1;
    }

    // convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++) {
        p = name[i];
        for (j = 0; j < (int)p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';  // remove the last dot
    return name;
}

void unpack_dns_packet(unsigned char *buf) {
    PRINT_Light_Red(" DNS Header:\n");

    unsigned char *reader;
    int i, j;

    struct DNS_HEADER *dns = NULL;

    dns = (struct DNS_HEADER *)buf;

    printf("Questions\t: %d\n", ntohs(dns->q_count));
    printf("Answer PRs\t: %d\n", ntohs(dns->ans_count));
    printf("Authority PRs\t: %d\n", ntohs(dns->auth_count));
    printf("Additional RPs\t: %d\n", ntohs(dns->add_count));

    printf("Queries\t\t: %d\n", ntohs(dns->q_count));
    // start reading questions
    unsigned char *p = buf + sizeof(struct DNS_HEADER);
    if (ntohs(dns->q_count) > 1) return;

    // convert 3www6google3com0 to www.google.com
    char *qname = malloc(sizeof(char) * 256);
    i = 0;
    int cnt = *p++;
    while (cnt > 0) {
        qname[i++] = *p++;
        cnt--;
        if (cnt == 0) {
            cnt = *p++;
            qname[i++] = '.';
        }
    }
    // remove last dot
    qname[i - 1] = '\0';
    if (*(p - 1) != 0) {
        exit(1);
    }
    printf("  %s: ", qname);

    // p now point to type and class field
    struct QUESTION *qinfo = (struct QUESTION *)p;
    printf("type ");
    switch (ntohs(qinfo->qtype)) {
        case T_A:
            printf("A");
            break;  // Ipv4 address
        case T_NS:
            printf("NS");
            break;  // Nameserver
        case T_CNAME:
            printf("CNAME");
            break;  // canonical name
        case T_SOA:
            printf("SOA");
            break; /* start of authority zone */
        case T_PTR:
            printf("PTR");
            break; /* domain name pointer */
        case T_MX:
            printf("MX");
            break;  // Mail server
        case T_AAAA:
            printf("AAAA");
            break;  // IPv6 address
        default:
            printf("Unkown");
            break;
    }
    printf("(%d), ", ntohs(qinfo->qtype));

    printf("class ");
    switch (ntohs(qinfo->qclass)) {
        case 1:
            printf("IN");
            break;
        default:
            printf("Unkown");
            break;
    }
    printf("(%d)\n", ntohs(qinfo->qclass));

    if (ntohs(dns->ans_count) == 0) {
        return;
    }
    // p now point to answer field
    p = p + sizeof(struct QUESTION);

    reader = p;
    // Start reading answers
    int stop = 0;
    struct RES_RECORD answers[20], auth[20], addit[20];

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        answers[i].name = readDNSName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 1)  // if its an ipv4 address
        {
            answers[i].rdata =
                (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++) {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        } else {
            answers[i].rdata = readDNSName(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    // read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        auth[i].name = readDNSName(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        auth[i].rdata = readDNSName(reader, buf, &stop);
        reader += stop;
    }

    // read additional
    for (i = 0; i < ntohs(dns->add_count); i++) {
        addit[i].name = readDNSName(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        if (ntohs(addit[i].resource->type) == 1) {
            addit[i].rdata =
                (unsigned char *)malloc(ntohs(addit[i].resource->data_len));
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        } else {
            addit[i].rdata = readDNSName(reader, buf, &stop);
            reader += stop;
        }
    }

    // print answers
    struct sockaddr_in a;
    printf("Answers : %d \n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++) {
        printf("  Name : %s ", answers[i].name);
        if (ntohs(answers[i].resource->type) == T_A)  // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            a.sin_addr.s_addr = (*p);  // working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        if (ntohs(answers[i].resource->type) == 5) {
            // Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }
        printf("\n");
    }

    // print authorities
    printf("Authoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2) {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }

    // print additional resource records
    printf("Additional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++) {
        printf("Name : %s ", addit[i].name);
        if (ntohs(addit[i].resource->type) == 1) {
            long *p;
            p = (long *)addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }

    return;
}

void unpack_tcp_packet(unsigned char *buf) {
    PRINT_Light_Green(" TCP Header:\n");

    struct TCPPack *packet = (struct TCPPack *)buf;
    printf("Source Port\t: %d\n", ntohs(packet->srcPort));
    printf("Destination Port: %d\n", ntohs(packet->dstPort));

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
}

void unpack_udp_packet(unsigned char *buf) {
    PRINT_Light_Green(" UDP Header:\n");

    struct UDPPack *packet = (struct UDPPack *)buf;
    printf("Source Port\t: %d\n", ntohs(packet->srcPort));
    printf("Destination Port: %d\n", ntohs(packet->dstPort));

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
    PRINT_Light_Cyan(" ICMP Header:\n");

    struct ICMPPack *packet = (struct ICMPPack *)buf;

    printf("Type\t: %d ", packet->type);
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

    printf("Code\t: %d ", packet->code);
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
        printf("Identifier (BE)\t:%d (0x%04x)\n", ntohs(packet->un.echo.id),
               ntohs(packet->un.echo.id));
        printf("Identifier (LE)\t:%d (0x%04x)\n", packet->un.echo.id,
               packet->un.echo.id);

        printf("Sequence Number (BE)\t:%d (0x%04x)\n",
               ntohs(packet->un.echo.sequence),
               ntohs(packet->un.echo.sequence));
        printf("Sequence Number (LE)\t:%d (0x%04x)\n", packet->un.echo.sequence,
               packet->un.echo.sequence);
    }

    printf("Data: (%d bytes)\n", len);
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

int main(int argc, char *argv[]) {
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
        printf("-------------------------------------\n");
        unpack_eth_packet(buffer);
    }
    return -1;
}
