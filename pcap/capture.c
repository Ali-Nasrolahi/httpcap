#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ANY           1
#define HTTP_PORT     "80"
#define MAX_PRINT_LEN 100  // Limit printed payload length

#ifdef ANY
#define DEVICE    "any"
#define LINK_HLEN 16  // Linux cooked socket (DLT_LINUX_SLL)
#else
#define DEVICE    "capture"
#define LINK_HLEN 14  // Ethernet (DLT_EN10MB)
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static const char *http_methods[] = {"GET ",     "POST ",    "HEAD ",  "PUT ",   "DELETE ",
                                     "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ", "HTTP/"};

static inline bool is_http(const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len < 4) return false;
    for (size_t i = 0; i < ARRAY_SIZE(http_methods); ++i) {
        size_t method_len = strlen(http_methods[i]);
        if (payload_len >= method_len &&
            !strncmp((const char *)payload, http_methods[i], method_len)) {
            return true;
        }
    }
    return false;
}

void packet_handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *packet)
{
    struct iphdr *ip_h = (struct iphdr *)(packet + LINK_HLEN);
    struct tcphdr *tcp_h = (struct tcphdr *)(packet + LINK_HLEN + ip_h->ihl * 4);

    const uint8_t *payload = packet + LINK_HLEN + ip_h->ihl * 4 + tcp_h->doff * 4;
    uint32_t payload_len = h->caplen - (payload - packet);

    if (is_http(payload, payload_len)) {
        printf("HTTP packet: %d->%d, len %u, data: %.*s\n", ntohs(tcp_h->source),
               ntohs(tcp_h->dest), payload_len,
               (int)(payload_len > MAX_PRINT_LEN ? MAX_PRINT_LEN : payload_len), payload);
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(DEVICE, BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device %s: %s\n", DEVICE, errbuf);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port " HTTP_PORT, 0, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}