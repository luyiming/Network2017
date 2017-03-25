#ifndef MYTYPE_H
#define MYTYPE_H
#include <sys/types.h>  // uintX_t data types


/*----------------------------- udp PACKET ----------------------------------*/
#pragma pack(1)
struct UDPPack {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;  // total length
    uint16_t checksum;
    uint8_t payload;
};
#pragma pack(0)

/*----------------------------- tcp PACKET ----------------------------------*/
#pragma pack(1)
struct TCPPack {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t sequence;
    uint32_t ack;
    union {
        struct {
            uint8_t offset : 4;  // times 4
            uint16_t dont_care : 12;
        };
        uint16_t flags;
    };
#define FIN_BIT 0x1
#define SYN_BIT 0x2
#define RESET_BIT 0x4
#define PUSH_BIT 0x8
#define ACK_BIT 0x10
#define URGENT_BIT 0x20
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
    uint8_t payload;
};
#pragma pack(0)

/*---------------------------- ICMP PACKET ----------------------------------*/
#pragma pack(1)
struct ICMPPack {
    uint8_t type; /* message type */
    uint8_t code; /* type sub-code */
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;               /* echo datagram */
        unsigned int gateway; /* gateway address */
        struct {
            uint16_t __unused;
            uint16_t mtu;
        } frag; /* path mtu discovery */
    } un;
    uint8_t data[56];
};
#pragma pack(0)

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4   /* Source Quench		*/
#define ICMP_REDIRECT 5        /* Redirect (change route)	*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIME_EXCEEDED 11  /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12  /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable		*/
#define ICMP_HOST_UNREACH 1 /* Host Unreachable		*/
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH 3 /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED 5    /* Source Route failed		*/
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13   /* Packet filtered */
#define ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define ICMP_PREC_CUTOFF 15    /* Precedence cut off */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET 0     /* Redirect Net			*/
#define ICMP_REDIR_HOST 1    /* Redirect Host		*/
#define ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL 0      /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME 1 /* Fragment Reass time exceeded	*/

/*---------------------------- IP PACKET -------------------------------------*/
#pragma pack(1)
struct IPPack {
    uint8_t header_length : 4, /* header length */
        version : 4;           /* IP version */
    uint8_t TOS;               /* type of service */
    uint16_t length;           /* total length */
    uint16_t id;               /* identification */
    uint8_t frag_offset[2];
    /* fragment offset field */  // 3 bits flags and 13 bits fragment-offset
#define IP_DF 0x4000             /* dont fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
    uint8_t TTL;                 /* time to live */
    uint8_t protocol;            /* protocol */
    uint16_t checksum;           /* checksum */
    uint8_t srcIP[4];            /* source and dest address */
    uint8_t dstIP[4];
    uint8_t payload[1500];
};
#pragma pack()

/*--------------------------- ETHERNET PACKET --------------------------------*/
#pragma pack(1)
struct EthPack {
    // Eth head 14 bytes
    uint8_t dstAddr[6];
    uint8_t srcAddr[6];
    uint16_t type;
    // ip packet
    struct IPPack ipPack;
};
#pragma pack()

#pragma pack(1)
struct EthArpPack {
    uint8_t dstAddr[6];
    uint8_t srcAddr[6];
    uint8_t type[2];
    uint8_t hrd[2];
    uint8_t protocol[2];
    uint8_t hrdLength;
    uint8_t proLength;
    uint8_t opcode[2];
    uint8_t srcHrdAddr[6];
    uint8_t srcIPAddr[4];
    uint8_t dstHrdAddr[6];
    uint8_t dstIPAddr[4];
};
#pragma pack()

#endif
