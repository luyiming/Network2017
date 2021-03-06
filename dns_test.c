#include <stdio.h>
#include "dns.h"

#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <stdio.h>       //printf
#include <stdlib.h>      //malloc
#include <string.h>      //strlen
#include <sys/socket.h>  //you know what this is for
#include <unistd.h>      //getpid

struct sockaddr_in a;
int main(int argc, char *argv[]) {
    char hostname[100];

    // Get the hostname from the terminal
    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    // Now get the ip of this hostname , A record
    if (getHostByName(hostname, (struct sockaddr_in *)&a) == 1) {
        printf("%s\n", inet_ntoa(a.sin_addr));
    }

    return 0;
}
