#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

typedef unsigned char BYTE;

#define BUFFER_SIZE 2048
int sockfd;
struct sockaddr_in dest_addr;

unsigned short checksum(void *data, size_t len) {
    unsigned long sum = 0;
    unsigned short *p = (unsigned short *)data;
    while (len > 1) {
        sum = sum + *p;
        p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(BYTE *)p;
    }
    while ((sum >> 16) != 0) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ~(unsigned short)sum;
}

void pack_icmp(void *buf, size_t buf_len) {
    static unsigned short count = 1;
    assert(buf_len > sizeof(struct icmp));
    memset(buf, 0, buf_len);
    struct icmp *icmp = (struct icmp *)buf;
    // pack icmp data
    gettimeofday((struct timeval *)icmp->icmp_data, NULL);
    icmp->icmp_type  = ICMP_ECHO;
    icmp->icmp_code  = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id    = getpid();
    icmp->icmp_seq   = htons(count++);
    BYTE *p = (BYTE*)icmp->icmp_data + sizeof(struct timeval);
    for (int i = 0; i < 48/3; i++) {
        *p++ = 'l';
        *p++ = 'y';
        *p++ = 'm';
    }
    icmp->icmp_cksum = checksum((void *)icmp, 64);
}

void send_icmp(int sockfd, struct sockaddr_in dest_addr) {
    BYTE icmp_buf[64];
    pack_icmp(icmp_buf, 64);
    sendto(sockfd, icmp_buf, 64, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

void receive_pack(int sockfd) {
    char ip_source[INET_ADDRSTRLEN];
    struct timeval *tvstart, *tvend = (struct timeval*)malloc(sizeof(struct timeval));
    BYTE recv_buf[BUFFER_SIZE];
    while (1) {
        memset(recv_buf, 0, BUFFER_SIZE);
        if (recvfrom(sockfd, recv_buf, BUFFER_SIZE, 0, NULL, NULL) < 0) {
            if (errno == EINTR)  // interrupted system call
                continue;
            else {
                perror("recvfrom");
                exit(1);
            }
        }
        gettimeofday(tvend, NULL);

        struct ip *p_ip = (struct ip *)recv_buf;
        unsigned short iph_length = (p_ip->ip_hl) * 4;
        unsigned short icmp_length = ntohs(p_ip->ip_len) - iph_length;
        struct icmp *p_icmp = (struct icmp *)((BYTE *)p_ip + iph_length);

        // check sum
        unsigned short sum_recv = p_icmp->icmp_cksum;
        p_icmp->icmp_cksum = 0;
        unsigned short sum_calc = checksum(p_icmp, icmp_length);
        if (sum_calc != sum_recv) {
            printf("checksum error: sum_recv = %d/0x%x\tsum_cal = %d/0x%x\n", sum_recv, sum_recv, sum_calc, sum_calc);
            continue;
        }

        switch (p_icmp->icmp_type) {
            case ICMP_ECHOREPLY: {
                inet_ntop(AF_INET, (void *)&(p_ip->ip_src), ip_source, INET_ADDRSTRLEN);
                tvstart = (struct timeval *)p_icmp->icmp_data;
                double delt_sec = (tvend->tv_sec - tvstart->tv_sec) + (tvend->tv_usec - tvstart->tv_usec) / 1000000.0;
                printf( "%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n",
                        icmp_length, ip_source, ntohs(p_icmp->icmp_seq), p_ip->ip_ttl, delt_sec * 1000);
                break;
            }
            case ICMP_TIME_EXCEEDED: {
                printf("time out\n");
                break;
            }
            case ICMP_DEST_UNREACH: {
                inet_ntop(AF_INET, (void *)&(p_ip->ip_src), ip_source, INET_ADDRSTRLEN);
                printf("From %s icmp_seq=%d Destination Net Unreachable\n",
                       ip_source, p_icmp->icmp_seq);
                break;
            }
        }
    }
    free(tvend);
}

void alarm_handler(int signo) {
    send_icmp(sockfd, dest_addr);
    alarm(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: ping address\n");
        return 0;
    }
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("socket:");
        return 0;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &dest_addr.sin_addr) != 1) {
        perror("inet_pton:");
        exit(1);
    }
    // set alarm
    struct sigaction newact, oldact;
    newact.sa_handler = alarm_handler;
    sigemptyset(&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction(SIGALRM, &newact, &oldact);
    alarm(1);

    receive_pack(sockfd);
}
