#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns.h"

/*
 * Perform a DNS query by sending a packet
 * */
int getHostByName(unsigned char *host, int query_type,
                  struct sockaddr_in *res_addr) {
    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;

    struct RES_RECORD answers[20];
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

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

    toDnsNameFormat(qname, host);
    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)];

    qinfo->qtype  = htons(query_type);
    qinfo->qclass = htons(1);  // its internet (lol)

    if (sendto(s, (char *)buf,
               sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) +
                   sizeof(struct QUESTION),
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
    reader = &buf[sizeof(struct DNS_HEADER) +
                  (strlen((const char *)qname) + 1) + sizeof(struct QUESTION)];

    // Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        answers[i].name = readName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == T_A)
        {
            answers[i].rdata =
                (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++) {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        } else {
            answers[i].rdata = readName(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    for (i = 0; i < ntohs(dns->ans_count); i++) {
        if (ntohs(answers[i].resource->type) == T_A)  // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            res_addr->sin_addr.s_addr = (*p);  // working without ntohl
            return 0;
        }
    }
    return -1;
}

u_char *readName(unsigned char *reader, unsigned char *buffer, int *count) {
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
    printf("get dns server %s\n", dns_server);
}

/**
 * [This will convert www.google.com to 3www6google3com
 * @method toDnsNameFormat
 * @param  dns_name        [description]
 * @param  host            [description]
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
