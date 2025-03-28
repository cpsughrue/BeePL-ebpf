#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * This eBPF program is attached as a Trafic Control classifier.
 * It uses bpf_skb_vlan_push to insert a VLAN tag into the packet.
 */
SEC("classifier")
int vlan_push_prog(struct __sk_buff *skb)
{
    __be16 vlan_proto = bpf_htons(ETH_P_8021Q); // 0x8100 = 
    __u16 vlan_tci = 100;

    if (bpf_skb_vlan_push(skb, vlan_proto, vlan_tci) < 0) {
        return TC_ACT_SHOT; // drop packet on error
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
