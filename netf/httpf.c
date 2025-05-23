#ifndef __KERNEL__
#define __KERNEL__
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

#define HTTP_PORT 80

static const char *http_methods[] = {"GET ",     "POST ",    "HEAD ",  "PUT ",   "DELETE ",
                                     "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ", "HTTP/"};

inline static bool is_http(const u8 *payload, u32 payload_len)
{
    if (payload_len < 4) return false;

    for (int i = 0; i < ARRAY_SIZE(http_methods); ++i) {
        size_t method_len = strlen(http_methods[i]);
        if (payload_len >= method_len && !strncmp(payload, http_methods[i], method_len)) {
            return true;
        }
    }
    return false;
}

static unsigned int hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u32 payload_offset, payload_len;
    u8 buf[64];

    if (!skb || !skb_network_header(skb)) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    if (skb->len < iph->ihl * 4 + sizeof(struct tcphdr)) return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    if (!tcph) return NF_ACCEPT;

    if (ntohs(tcph->source) != HTTP_PORT && ntohs(tcph->dest) != HTTP_PORT) return NF_ACCEPT;

    payload_offset = iph->ihl * 4 + tcph->doff * 4;
    if (payload_offset >= skb->len) return NF_ACCEPT;

    payload_len = ntohs(iph->tot_len) - payload_offset;
    payload_len = min(payload_len, (u32)sizeof(buf));

    if (payload_len > 0 && skb_copy_bits(skb, payload_offset, buf, payload_len) == 0) {
        if (is_http(buf, payload_len)) {
            pr_info("HTTP packet: %d->%d, len %u, data: %.*s\n", ntohs(tcph->source),
                    ntohs(tcph->dest), payload_len, payload_len, buf);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops hooks[] = {
    {
        .hook = hook,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_IPV4,
        .priority = 0,
    },
    {
        .hook = hook,
        .hooknum = NF_INET_POST_ROUTING,
        .pf = NFPROTO_IPV4,
        .priority = 0,
    },
};

static int __init httpf_init(void)
{
    struct net *net;
    int ret;

    for_each_net(net)
    {
        ret = nf_register_net_hooks(net, hooks, ARRAY_SIZE(hooks));
        if (ret < 0) {
            pr_err("Failed to register hooks in net namespace\n");
            goto cleanup;
        }
    }

    pr_info("Loaded!\n");
    return 0;

cleanup:
    for_each_net(net) { nf_unregister_net_hooks(net, hooks, ARRAY_SIZE(hooks)); }
    return ret;
}

static void __exit httpf_exit(void)
{
    struct net *net;

    for_each_net(net) { nf_unregister_net_hooks(net, hooks, ARRAY_SIZE(hooks)); }
    pr_info("Unloaded\n");
}

module_init(httpf_init);
module_exit(httpf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ali Nasrolahi <A.Nasrolahi01@gmail.com>");
MODULE_DESCRIPTION("Netfilter module to log HTTP packets");
MODULE_VERSION("0.1");