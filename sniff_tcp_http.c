#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

// HTTP 메시지(Payload) 출력을 위한 함수
void print_payload(const u_char *payload, int len) {
    if (len <= 0) return;
    
    printf("[HTTP Message (Payload)]\n   ");
    for(int i = 0; i < len; i++) {
        
        if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r') {
            putchar(payload[i]);
        } else {
            putchar('.');
        }
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 1. Ethernet 헤더 분석
    struct ethheader *eth = (struct ethheader *)packet;
    
    printf("==================================================\n");
    printf("[Ethernet Header]\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP 패킷인지 확인
    if (ntohs(eth->ether_type) == 0x0800) { 
        // 2. IP 헤더 분석 (Ethernet 헤더 크기만큼 포인터 이동)
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

        printf("[IP Header]\n");
        printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));   
        printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));    

        // TCP만 대상으로 진행
        if (ip->iph_protocol == IPPROTO_TCP) {
            
            // IP 헤더 길이 계산: ihl 필드는 4바이트(Word) 단위이므로 4를 곱함
            int ip_header_len = ip->iph_ihl * 4;

            // 3. TCP 헤더 분석 (IP 헤더 길이만큼 포인터 이동)
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
            
            printf("[TCP Header]\n");
        
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // TCP 헤더 길이 계산: offset 필드는 4바이트 단위이므로 4를 곱함
            int tcp_header_len = TH_OFF(tcp) * 4;

            // 4. HTTP Message (Application 데이터) 계산
            // 전체 IP 패킷 길이에서 IP 헤더 길이와 TCP 헤더 길이를 빼서 순수 페이로드 길이를 구함
            int total_ip_len = ntohs(ip->iph_len);
            int payload_len = total_ip_len - ip_header_len - tcp_header_len;

            if (payload_len > 0) {
                // 페이로드 시작 위치: TCP 헤더 시작점 + TCP 헤더 길이
                const u_char *payload = (u_char *)tcp + tcp_header_len;
                print_payload(payload, payload_len);
            } else {
                printf("[HTTP Message (Payload)]\n   No Payload data.\n");
            }
        }
    }
    printf("==================================================\n\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    
    // 요구사항: TCP 프로토콜만 대상. HTTP 패킷을 주로 잡기 위해 tcp port 80으로 필터 설정
    char filter_exp[] = "tcp port 80"; 
    bpf_u_int32 net;

    // Step 1: 네트워크 인터페이스 열기
    // enp03은 자신의 LAN 카드 번호에 맞게 변경
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return(2);
    }

    // Step 2: BPF 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    printf("Starting packet capture (Filter: %s)...\n", filter_exp);

    // Step 3: 패킷 캡처 루프
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}