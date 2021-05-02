#include "ft_traceroute.h"

static void fill_args(char *argv[], int *last_arg);
static void get_ips(int i);
static void create_sockets();
static void send_udp(struct timeval *send_time);
static void catcher(int i, struct timeval *send_time, char *last_ip);

struct data_t metadata;

int main(int argc, char *argv[])
{
    char ip_buffer[INET_ADDRSTRLEN];
    char last_ip[NI_MAXHOST];
    int last_arg;


    if (argc < 2)
    {
        fprintf(stderr, "usage: %s [-hfmqwn] host [bytes per packet]\n", argv[0]);
        fprintf(stderr, "          [-h ???]\n");
        fprintf(stderr, "          [-f first_ttl]\n");
        fprintf(stderr, "          [-m max_ttl]\n");
        fprintf(stderr, "          [-q nqueries]\n");
        fprintf(stderr, "          [-w waittime]\n");
        fprintf(stderr, "          [-n]\n");
        exit(1);
    }           

    memset(ip_buffer, 0, sizeof ip_buffer);
    memset(last_ip, 0, sizeof last_ip);

    metadata.args = 0;
    metadata.n_queries_per_hops = 3;
    metadata.wait_time = 5;
    metadata.first_ttl = 1;
    metadata.max_ttl = 30;
    metadata.server_ip = ip_buffer;
    metadata.server_port = 33434;

    fill_args(&argv[1], &last_arg);

    if (argc - last_arg < 2)
    {
        fprintf(stderr, "Specify \"host\" missing argument.\n");
        exit(1);
    }

    metadata.packet_size = argc - last_arg < 3 ? 60 : atoi(argv[last_arg + 2]);
    metadata.server_domain = argv[last_arg + 1];

    if (metadata.first_ttl < 1 || metadata.first_ttl > 255)
    {
        fprintf(stderr, "first ttl must be greater than 0 and smaller than 256\n");
        exit(1);
    }
    if (metadata.max_ttl < 1 || metadata.max_ttl > 255 || metadata.max_ttl < metadata.first_ttl)
    {
        fprintf(stderr, "max ttl must be greater than 0 and smaller than 256 and greater then first ttl\n");
        exit(1);
    }
    if (metadata.wait_time < 0 || metadata.wait_time > 86400)
    {
        fprintf(stderr, "wait time must be greater or equal than 0, smaller or equal than 86400 and greater\n");
        exit(1);
    }
    if (metadata.n_queries_per_hops < 1)
    {
        fprintf(stderr, "n_queries_per_hops ttl must be greater than 0\n");
        exit(1);
    }
    if (metadata.n_queries_per_hops < 1)
    {
        fprintf(stderr, "n_queries_per_hops ttl must be greater than 0\n");
        exit(1);
    }
    if (metadata.packet_size > 49999)
    {
        fprintf(stderr, "n_queries_per_hops ttl must be smaller than 50000\n");
        exit(1);
    }
    if (metadata.packet_size < 28)
    {
        metadata.packet_size = 28;
    }

    printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n", metadata.server_domain, metadata.server_ip, metadata.max_ttl, metadata.packet_size);
    for (int i = metadata.first_ttl; i <= metadata.max_ttl; ++i)
    {
        printf("%d", i);
        fflush(stdout);
        get_ips(i);
        create_sockets(i);

        struct timeval send_time[metadata.n_queries_per_hops];
        for (int j = 0; j < metadata.n_queries_per_hops; ++j)
        {
            send_udp(&send_time[j]);
            catcher(i, &send_time[j], last_ip);
        }
        printf("\n");
    }
    return (0);
}

static void fill_args(char *argv[], int *last_arg)
{
    args_t  args[NBR_OF_ARGS];

    args[0].name = "-h";
    args[0].value = ARG_H;
    args[1].name = "-f";
    args[1].value = ARG_F;
    args[2].name = "-m";
    args[2].value = ARG_M;
    args[3].name = "-q";
    args[3].value = ARG_Q;
    args[4].name = "-w";
    args[4].value = ARG_W;
    args[5].name = "-n";
    args[5].value = ARG_N;
    *last_arg = 0;
    for (int i = 0; argv[i] != NULL; ++i)
    {
        for (int j = 0; j < NBR_OF_ARGS; ++j)
        {
            if (strcmp(argv[i], args[j].name) == 0)
            {
                *last_arg = i + 2;
                metadata.args |= args[j].value;
                switch (args[j].value)
                {
                    case ARG_F:
                        metadata.first_ttl = atoi(argv[i + 1]);
                        break ;
                    case ARG_M:
                        metadata.max_ttl = atoi(argv[i + 1]);
                        break ;
                    case ARG_Q:
                        metadata.n_queries_per_hops = atoi(argv[i + 1]);
                        break ;
                    case ARG_W:
                        metadata.wait_time = atoi(argv[i + 1]);
                        break ;
                    default:
                        *last_arg = i + 1;
                        break ;
                }
            }
        }
    }
}

static void get_ips(int i)
{
    struct addrinfo hints, *res;
    int rc;
    const char *prc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port[50];
    sprintf(port, "%d", metadata.server_port + i);
    rc = getaddrinfo(metadata.server_domain, port, &hints, &res);
    if (rc != 0)
    {
        fprintf(stderr, "ft_ping: cannot resolve %s: unknow host\n", metadata.server_domain);
        exit(1);
    }

    // only check the first elem of the res list
    metadata.server_addr = *(res->ai_addr);
    
    prc = inet_ntop(AF_INET, &((struct sockaddr_in *)&metadata.server_addr)->sin_addr, metadata.server_ip, INET_ADDRSTRLEN);
    if (prc == NULL)
    {
        perror("ping: inet_ntop");
        exit(1);
    }
}

static void create_sockets(int ttl)
{
    struct timeval tv;
    int rc, on;

    metadata.udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (metadata.udp_socket == -1)
    {
        perror("ping: socket");
        exit(1);
    }

    rc = connect(metadata.udp_socket, &metadata.server_addr, sizeof metadata.server_addr);
    if (rc == -1)
    {
        perror("ft_traceroute: connect");
        exit(1);
    }

    setsockopt(metadata.udp_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl);

    metadata.icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (metadata.icmp_socket == -1)
    {
        perror("ping: socket");
        exit(1);
    }

    on = IP_PMTUDISC_DO;
    setsockopt(metadata.icmp_socket, SOL_IP, IP_MTU_DISCOVER, &on, sizeof on);
    setsockopt(metadata.icmp_socket, SOL_IP, IP_RECVERR, &on, sizeof on);
    setsockopt(metadata.icmp_socket, SOL_IP, IP_RECVTTL, &on, sizeof on);
    tv.tv_sec = metadata.wait_time;
    tv.tv_usec = metadata.wait_time == 0;
    setsockopt(metadata.icmp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

static void send_udp(struct timeval *send_time)
{
    uint8_t outpack[metadata.packet_size - IP_HEADER_SIZE - UDP_HEADER_SIZE];
    int rc;

    for (int i = 0; i < (int)sizeof outpack; ++i)
    {
        outpack[i] = 64 + i;
    }

    // print_tab_in_hex("send", outpack, sizeof outpack);

    gettimeofday(send_time, NULL);
    rc = sendto(metadata.udp_socket, outpack, sizeof outpack, 0, &metadata.server_addr, sizeof metadata.server_addr);
    if (rc == -1)
    {
        perror("ping: sendto");
    }
}

static void catcher(int i, struct timeval *send_time, char *last_ip)
{
    struct timeval recv_time;
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof src_addr;
    uint8_t msg_buffer[112];
    struct icmp *reply;
    int rc;

    memset(&msg_buffer, 0, sizeof msg_buffer);
    rc = recvfrom(metadata.icmp_socket, msg_buffer, sizeof msg_buffer, 0, (struct sockaddr *)&src_addr, &addrlen);
    if (rc < 0)
    {
        if (errno == EAGAIN)
        {
            printf("  *");
            fflush(stdout);
            return ;
        }
        perror("ping: read");
        exit(1);
	}
    gettimeofday(&recv_time, NULL);

    // print_tab_in_hex("msg", msg_buffer, sizeof msg_buffer);
    // print_tab_in_hex("sender", (uint8_t *)&src_addr, sizeof src_addr);

    reply = (struct icmp *)&msg_buffer[IP_HEADER_SIZE];

    /* if response is valid */
    if (reply->icmp_type == ICMP_TIME_EXCEEDED /* && reply->icmp_id == getpid() */ || (reply->icmp_type == ICMP_DEST_UNREACH && reply->icmp_code == ICMP_PORT_UNREACH))
    {
        struct in_addr *in = (struct in_addr *)&msg_buffer[12];
        char *ip = inet_ntoa(*in);
        struct addrinfo hints, *res;
        char port[50], hostname[NI_MAXHOST];

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_CANONNAME;

        sprintf(port, "%d", metadata.server_port + i);
        rc = getaddrinfo(ip, port, &hints, &res);
        if (rc != 0)
        {
            fprintf(stderr, "ft_ping: cannot resolve %s: unknow host\n", ip);
            exit(1);
        }

        rc = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0); 
        if (rc == -1)
        {
            fprintf(stderr, "ft_ping: getnameinfo\n");
            exit(1);
        }

        if (strcmp(last_ip, ip) != 0)
        {
            metadata.args & ARG_N ? printf("  %s", ip): printf("  %s (%s)", hostname, ip);
            fflush(stdout);
            memcpy(last_ip, ip, strlen(ip));
            last_ip[strlen(ip)] = '\0';
        }

        double diff = (recv_time.tv_sec - send_time->tv_sec) * UINT32_MAX + (recv_time.tv_usec - send_time->tv_usec);
        printf("  %0.3f ms", diff / 1000.0);
        fflush(stdout);
        // ++metadata.n_packet_recv;
    }
    if (reply->icmp_type == ICMP_DEST_UNREACH && reply->icmp_code == ICMP_PORT_UNREACH)
    {
        exit(0);
    }
}
