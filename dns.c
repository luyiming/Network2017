#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns.h"
#include "type.h"
#include "util.h"

void get_dns_servers();
void toDnsNameFormat(unsigned char *, unsigned char *);
unsigned char *readDNSName(unsigned char *, unsigned char *, int *);

/**
 * unpack dns packet, print correspoing data
 * @method unpack_dns_packet
 * @param  buf               [pointer to the beginning of dns data field]
 */
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
    printf(" -> %s: ", qname);

    // p now point to type and class field
    struct DNS_QUESTION *qinfo = (struct DNS_QUESTION *)p;
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
    p = p + sizeof(struct DNS_QUESTION);

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
        printf(" -> Name : %s ", answers[i].name);
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
        printf(" -> Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2) {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }

    // print additional resource records
    printf("Additional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++) {
        printf(" -> Name : %s ", addit[i].name);
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

/**
 * Perform a DNS query by sending a UDP packet
 * get the first query result
 * @method getHostByName
 * @param  host          [url string]
 * @param  res_addr      [struct sockaddr_in data]
 * @return               [1 if succeed, -1 if fail]
 */
int getHostByName(char *host, struct sockaddr_in *res_addr) {
    // Get the DNS servers from the resolv.conf file
    get_dns_servers();

    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;

    struct RES_RECORD answers[20];
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct DNS_QUESTION *qinfo = NULL;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server);

    // Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;      // This is a query
    dns->opcode = 0;  // This is a standard query
    dns->aa = 0;      // Not Authoritative
    dns->tc = 0;      // This message is not truncated
    dns->rd = 1;      // Recursion Desired
    dns->ra = 0;      // Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);  // we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // point to the query portion
    qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];

    toDnsNameFormat(qname, (unsigned char*)host);
    qinfo = (struct DNS_QUESTION *)&buf[sizeof(struct DNS_HEADER) +
                                        (strlen((const char *)qname) + 1)];

    qinfo->qtype = htons(T_A);
    qinfo->qclass = htons(1);  // its internet (lol)

    if (sendto(s, (char *)buf,
               sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) +
                   sizeof(struct DNS_QUESTION),
               0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        return -1;
    }

    // Receive the answer
    i = sizeof dest;
    if (recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest,
                 (socklen_t *)&i) < 0) {
        perror("recvfrom failed");
        return -1;
    }

    dns = (struct DNS_HEADER *)buf;

    // move ahead of the dns header and the query field
    reader =
        &buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) +
             sizeof(struct DNS_QUESTION)];

    // Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        answers[i].name = readDNSName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == T_A) {
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

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        if (ntohs(answers[i].resource->type) == T_A)  // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            res_addr->sin_addr.s_addr = (*p);  // working without ntohl
            return 1;
        }
    }
    return -1;
}

/**
 * read DNS-type name in *reder
 * @method readDNSName
 * @param  reader      [point to name field]
 * @param  buffer      [dns packet buffer]
 * @param  count       [return count]
 * @return             [description]
 */
unsigned char *readDNSName(unsigned char *reader, unsigned char *buffer,
                           int *count) {
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
            jumped = 1;  // we have jumped to another location so counting wont
                         // go up!
        } else {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0) {
            *count = *count + 1;  // if we havent jumped to another location
                                  // then we can count up
        }
    }

    name[p] = '\0';  // string complete
    if (jumped == 1) {
        *count = *count +
                 1;  // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
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

/**
 * [Get the DNS servers from /etc/resolv.conf file on Linux]
 * @method get_dns_servers
 */
void get_dns_servers() {
    FILE *fp;
    char line[200], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        printf("Failed opening /etc/resolv.conf file \n");
    }
    while (fgets(line, 200, fp)) {
        if (line[0] == '#') {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0) {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
            strcpy(dns_server, p);
            break;
        }
    }
    // printf("get dns server %s\n", dns_server);
}

/**
 * [This will convert www.google.com to 3www6google3com
 * @method toDnsNameFormat
 * @param  dns_name        [output: dns type name]
 * @param  host            [input: url]
 */
void toDnsNameFormat(unsigned char *dns_name, unsigned char *host) {
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++) {
        if (host[i] == '.') {
            *dns_name++ = i - lock;
            for (; lock < i; lock++) {
                *dns_name++ = host[lock];
            }
            lock++;
        }
    }
    *dns_name = '\0';
}
