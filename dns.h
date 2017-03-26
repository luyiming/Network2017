#ifndef DNS_H
#define DNS_H
#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>

/**
 * Perform a DNS query by sending a UDP packet
 * get the first query result
 * @method getHostByName
 * @param  host          [url string]
 * @param  res_addr      [struct sockaddr_in data]
 * @return               [1 if succeed, -1 if fail]
 */
int getHostByName(char *host, struct sockaddr_in *res_addr);

/**
 * unpack dns packet, print correspoing data
 * @method unpack_dns_packet
 * @param  buf               [pointer to the beginning of dns data field]
 */
void unpack_dns_packet(unsigned char *buf);

/**
 * DNS query types
 */
#define T_A 1        // Ipv4 address
#define T_NS 2       // Nameserver
#define T_CNAME 5    // canonical name
#define T_SOA 6      // start of authority zone
#define T_PTR 12     // domain name pointer
#define T_MX 15      // Mail server
#define T_AAAA 0x1c  // IPv6 address

// List of DNS Servers registered on the system
char dns_server[100];

// DNS header structure
struct DNS_HEADER {
    uint16_t id;  // identification number
    union {
        uint16_t flags;
        struct {
            uint8_t rd : 1;      // recursion desired
            uint8_t tc : 1;      // truncated message
            uint8_t aa : 1;      // authoritive answer
            uint8_t opcode : 4;  // purpose of message
            uint8_t qr : 1;      // query/response flag
            uint8_t rcode : 4;   // response code
            uint8_t cd : 1;      // checking disabled
            uint8_t ad : 1;      // authenticated data
            uint8_t z : 1;       // its z! reserved
            uint8_t ra : 1;      // recursion available
        };
    };
    uint16_t q_count;     // number of question entries
    uint16_t ans_count;   // number of answer entries
    uint16_t auth_count;  // number of authority entries
    uint16_t add_count;   // number of resource entries
};

// Constant sized fields of query structure
struct DNS_QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Structure of a Query
typedef struct {
    unsigned char *name;
    struct DNS_QUESTION *ques;
} QUERY;

#endif
