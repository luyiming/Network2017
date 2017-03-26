#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "dns.h"

typedef unsigned char BYTE;

#define BUFFER_SIZE 2048

struct globalArgs_t {
    int nr_transmitted, nr_received;  // number of packets transmitted/received
    int sockfd;                       // socket file descriptor
    struct sockaddr_in dest_addr;     // destination ipv4 address
    unsigned int count;               // number of packets to be received
    char *address;                    // destination address string
    clock_t start_time, end_time;     // time of program start/end
    double max_time, min_time, avg_time;  // statistics
} globalArgs;

static const char *optString = "c:";
void parse_opt(int argc, char **argv);

unsigned short checksum(void *data, size_t len);
void pack_icmp_ping(void *buf, size_t buf_len);
void send_ping();
void receive_ping();
void alarm_handler(int signo);
void exit_handler(int gisno);

int main(int argc, char *argv[]) {
    parse_opt(argc, argv);
    globalArgs.nr_received = globalArgs.nr_transmitted = 0;
    globalArgs.start_time = clock();
    globalArgs.avg_time = 0;
    globalArgs.address = argv[optind];

    if ((globalArgs.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("create socket:");
        return -1;
    }

    memset(&globalArgs.dest_addr, 0, sizeof(globalArgs.dest_addr));
    globalArgs.dest_addr.sin_family = AF_INET;
    //  get ipv4 address
    if (inet_pton(AF_INET, globalArgs.address,
                  &globalArgs.dest_addr.sin_addr) == 0) {
        // Now get the ip of the hostname
        if (getHostByName(globalArgs.address,
                          (struct sockaddr_in *)&globalArgs.dest_addr) != 1) {
            printf("error getting ipv4 address\n");
            exit(1);
        }
    }

    // signal handle
    struct sigaction time_act, int_act;
    sigemptyset(&time_act.sa_mask);
    time_act.sa_flags = int_act.sa_flags = 0;
    time_act.sa_handler = alarm_handler;
    int_act.sa_handler = exit_handler;
    sigaction(SIGALRM, &time_act, NULL);
    sigaction(SIGINT, &int_act, NULL);

    // start sending
    char ipstring[128];
    inet_ntop(AF_INET, (void *)&globalArgs.dest_addr.sin_addr, ipstring,
              sizeof(globalArgs.dest_addr));
    printf("PING %s (%s) 56(84) bytes of data.\n", argv[1], ipstring);
    send_ping();
    alarm(1);

    // star listening
    receive_ping();
}

/**
 * parse command options
 * @method parse_opt
 * @param  argc      [main argc]
 * @param  argv      [main argv]
 */
void parse_opt(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: ping [-c count] [-i interval] destination");
        exit(1);
    }
    globalArgs.count = -1;
    int opt = getopt(argc, argv, optString);
    while (opt != -1) {
        switch (opt) {
            case 'c':
                globalArgs.count = atoi(optarg);
                break;
            default:
                /* You won't actually get here. */
                break;
        }
        opt = getopt(argc, argv, optString);
    }
    if (optind != argc - 1) {
        printf("Usage: ping [-c count] [-i interval] destination");
        exit(1);
    }
}

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

void pack_icmp_ping(void *buf, size_t buf_len) {
    static unsigned short count = 1;
    assert(buf_len > sizeof(struct icmp));
    memset(buf, 0, buf_len);
    struct icmp *icmp = (struct icmp *)buf;
    // pack icmp data
    gettimeofday((struct timeval *)icmp->icmp_data, NULL);
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = getpid();
    icmp->icmp_seq = htons(count++);
    BYTE *p = (BYTE *)icmp->icmp_data + sizeof(struct timeval);
    for (int i = 0; i < 48 / 3; i++) {
        *p++ = 'l';
        *p++ = 'y';
        *p++ = 'm';
    }
    icmp->icmp_cksum = checksum((void *)icmp, 64);
}

void send_ping() {
    BYTE icmp_buf[64];
    pack_icmp_ping(icmp_buf, 64);
    sendto(globalArgs.sockfd, icmp_buf, 64, 0,
           (struct sockaddr *)&globalArgs.dest_addr,
           sizeof(globalArgs.dest_addr));
    globalArgs.nr_transmitted++;
}

void receive_ping() {
    char ip_source[INET_ADDRSTRLEN];
    struct timeval *tvstart;
    struct timeval *tvend = (struct timeval *)malloc(sizeof(struct timeval));
    BYTE recv_buf[BUFFER_SIZE];
    while (1) {
        if (globalArgs.count == 0) {
            exit_handler(0);
            exit(0);
        }

        memset(recv_buf, 0, BUFFER_SIZE);
        if (recvfrom(globalArgs.sockfd, recv_buf, BUFFER_SIZE, 0, NULL, NULL) < 0) {
            if (errno == EINTR)  // interrupted system call
                continue;
            else {
                perror("recvfrom");
                exit(1);
            }
        }
        gettimeofday(tvend, NULL);

        globalArgs.count--;

        struct ip *p_ip = (struct ip *)recv_buf;
        unsigned short iph_length = (p_ip->ip_hl) * 4;
        unsigned short icmp_length = ntohs(p_ip->ip_len) - iph_length;
        struct icmp *p_icmp = (struct icmp *)((BYTE *)p_ip + iph_length);

        // check sum
        unsigned short sum_recv = p_icmp->icmp_cksum;
        p_icmp->icmp_cksum = 0;
        unsigned short sum_calc = checksum(p_icmp, icmp_length);
        if (sum_calc != sum_recv) {
            printf("checksum error: sum_recv = %d/0x%x\tsum_cal = %d/0x%x\n",
                   sum_recv, sum_recv, sum_calc, sum_calc);
            continue;
        }

        switch (p_icmp->icmp_type) {
            case ICMP_ECHOREPLY: {
                inet_ntop(AF_INET, (void *)&(p_ip->ip_src), ip_source,
                          INET_ADDRSTRLEN);
                tvstart = (struct timeval *)p_icmp->icmp_data;
                double delt_sec =
                    (tvend->tv_sec - tvstart->tv_sec) +
                    (tvend->tv_usec - tvstart->tv_usec) / 1000000.0;

                globalArgs.nr_received++;
                if (globalArgs.nr_received == 1) {
                    globalArgs.max_time = globalArgs.min_time = delt_sec;
                }
                if (delt_sec < globalArgs.min_time) {
                    globalArgs.min_time = delt_sec;
                }
                if (delt_sec > globalArgs.max_time) {
                    globalArgs.max_time = delt_sec;
                }
                globalArgs.avg_time += delt_sec;
                printf("%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n",
                       icmp_length, ip_source, ntohs(p_icmp->icmp_seq),
                       p_ip->ip_ttl, delt_sec * 1000);
                break;
            }
            case ICMP_TIME_EXCEEDED: {
                printf("time out\n");
                break;
            }
            case ICMP_DEST_UNREACH: {
                inet_ntop(AF_INET, (void *)&(p_ip->ip_src), ip_source,
                          INET_ADDRSTRLEN);
                printf("From %s icmp_seq=%d Destination Net Unreachable\n",
                       ip_source, p_icmp->icmp_seq);
                break;
            }
        }
    }
    free(tvend);
}

/**
 * alarm signal handler
 * @method alarm_handler
 * @param  signo         [description]
 */
void alarm_handler(int signo) {
    send_ping();
    alarm(1);
}

/**
 * SIGINT signal handler
 * @method exit_handler
 * @param  gisno        [description]
 */
void exit_handler(int gisno) {
    globalArgs.end_time = clock();
    printf("\n");
    printf("--- %s ping statistics ---\n", globalArgs.address);
    printf(
        "%d packets transmitted, %d received, %.0f%% packet loss, time %ldms\n",
        globalArgs.nr_transmitted, globalArgs.nr_received,
        (double)(globalArgs.nr_transmitted - globalArgs.nr_received) /
            globalArgs.nr_received * 100,
        globalArgs.end_time - globalArgs.start_time);

    globalArgs.avg_time = globalArgs.avg_time / globalArgs.nr_received;
    printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", globalArgs.min_time * 1000,
           globalArgs.avg_time * 1000, globalArgs.max_time * 1000);
    exit(1);
}
