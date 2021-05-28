#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

// select
// htons
// ntohs
// bind

#include <stdlib.h>     // exit
#include <stdio.h>      // printf, fprintf, perror
#include <unistd.h>     // getpid, getuid
#include <stdlib.h>     // itoa
#include <string.h>     // memset
#include <errno.h>      // errno
#include <sys/time.h>   // gettimeofday
#include <sys/socket.h> // setsockopt, recvfrom, sendto, socket
#include <netdb.h>      // getaddrinfo
#include <arpa/inet.h>  // inet_ntoa inet_pton
#include <netinet/ip.h> // for next header
#include <netinet/ip_icmp.h> // struct icmp, some defines

#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define ICMP_HEADER_SIZE 8

#define NI_MAXHOST 1025

#define NBR_OF_ARGS 6
#define ARG_H 1
#define ARG_F 2
#define ARG_M 4
#define ARG_Q 8
#define ARG_W 16
#define ARG_N 32

typedef struct  args_s
{
    char        *name;
    uint8_t     value;
}               args_t;

struct data_t
{
    int udp_socket;
    int icmp_socket;
    uint8_t args;

    int packet_size;
    int n_queries_per_hops;
    int max_hops;
    int wait_time;
    int first_ttl;
    int max_ttl;
    
    struct sockaddr server_addr;
    char *server_ip;
    char *server_domain;
    int server_port;
};

uint16_t checksum(uint16_t *data, int data_len);

void print_addr(struct addrinfo addr);
void print_tab_in_hex(char *name, uint8_t *tab, int len);

#endif