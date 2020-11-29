#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <math.h>
#include <WinSock2.h>
#include <time.h>
#pragma comment(lib,"ws2_32")
#define MAX_PACKET 700

#define MAC_ADDR 6
#define DF(frag) (frag & 0x40)
#define MF(frag) (frag & 0x20)
#define FRAG_OFFSET(frag) (ntohs(frag) & (~0x6000))


//Structs
typedef struct pcapHeader {//노쓸모
    int magic;
    short major;
    short minor;
    int time_zone;
    int time_stamp;
    int snap_len;
    int link_type;
}pcap_H;

typedef struct Timeval_ {//시간
    long val_sec;
    long val_usec;
}Timeval;

typedef struct pktHeader_ {//시간+packet length
    Timeval time;
    unsigned int caplen;
    unsigned int len;
}pkt_H;

typedef struct Mac {//14bytes
    unsigned char MAC_DST[MAC_ADDR];
    unsigned char MAC_SRC[MAC_ADDR];
    unsigned short type;
}Mac;

typedef struct IP {
    unsigned char ver_hlen;
    unsigned char ecn;
    unsigned short tot;
    unsigned short id;
    unsigned short frag;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
}IP;

typedef struct TCP {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned long seq_num;
    unsigned long ack_num;
    unsigned short len_flag;//hlen(4)+reserved(6)+flag(6)
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;
    unsigned char option[40];
}TCP;

typedef struct UDP {//각각 16bit
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short totlen;
    unsigned short checksum;
}UDP;

//Functions
void Parse(FILE* fp);
void Parse_strt(FILE* fp);
void showFileHeader(pkt_H* ph);
void showMac(Mac mac);
unsigned short ntohs_(unsigned short value);
int showIP(IP ip);
void showTCP(TCP tcp,unsigned int trsp_len);
void showUDP(UDP udp, unsigned int trsp_len);
void flag_check(unsigned short len_flag);
void showOption(unsigned char* option,unsigned int real_hlen);

//전역
pkt_H packetHeader[MAX_PACKET];
int packetCount = 0;
int ip_hlen=0;
unsigned short max_tcp=0;
unsigned short max_udp=0;

int main() {
    FILE* fp;
    fp = fopen("packet3.pcap", "rb");
    Parse_strt(fp);
    fclose(fp);
    return 0;
}

void Parse_strt(FILE* fp) {
    //pcap의 쓸모없는 부분(24byte) 제거 -> 각 패킷의 TCP 헤더(MAC, Type) 읽기
    pcap_H noUse;
    fread(&noUse, sizeof(pcap_H), 1, fp);
    Parse(fp);//ip
}

void Parse(FILE* fp) {
    pkt_H* ph = packetHeader;
    //fp가 끝날 때까지 읽기 

    while (feof(fp) == 0) {
        if ((fread(ph, sizeof(pkt_H), 1, fp) != 1))
            break;//pkt_H -> caplen, len(actual packet len) 정보 있음 <- 전역
        if (packetCount == MAX_PACKET)
            break;

        //패킷이 아직 있는 경우 
        showFileHeader(ph); //time, caplen, actual len 출력
        Mac mac;
        fread(&mac, sizeof(mac), 1, fp); //mac 읽고,
        //showMac(mac);//mac 출력
        char tmpIP[65536];//ip packet의 최대 크기
        char tmpTransport[65536];//tcp,udp packet의 최대 크기
        //caplen = 실제 packet의 크기
        //caplen-(mac address and type which are 14 bytes) = 실제 IP부터의 크기
        fread(tmpIP, ph->caplen - 14, 1, fp);
        IP* ip = (IP*)tmpIP; //순수 IP header만 담을 변수 : ip
        int tcp_udp = showIP(*ip);//ip출력

        int ii = 0;
        for (int i = ip_hlen; i < ph->caplen; i++) {
            tmpTransport[ii] = tmpIP[i];
            ii++;
            /*
            tmpIP에는 ip header랑 뒤의 data(tcp header + payload)들도 들어있음
            그러니까, tmpTCP에 ip header인 hlen만큼 떼고, 그 이후의 데이터들을 저장해야함. 
            그래도 65536 byte 다 안하고, ip header 끝나고부터 caplen까지 옮겨담는다. 
            ++ ip_hlen은 전역변수로 설정해서 showIP 함수 이후에, ip_hlen에 실제 ip헤더의 크기(%d)가 저장되어 있도록!
            */
        }
        //caplen - 14(mac) - ip_hlen;
        unsigned int trsp_len = (ph->caplen) - 14 - ip_hlen;
        if (tcp_udp == 1) {
            TCP* tcp = (TCP*)tmpTransport;
            showTCP(*tcp,trsp_len);
        }
        else if (tcp_udp == 2) {
            UDP* udp = (UDP*)tmpTransport;
            showUDP(*udp, trsp_len);
        }
        else {
            printf("\nIt is not tcp or udp packet\n");
        }
    }
    printf("done done done max_tcp : %d\nmax_udp : %d\n", max_tcp,max_udp);
}



void showFileHeader(pkt_H* ph) {
    packetCount++; //<-전역

    time_t rawtime = ph->time.val_sec;
    //time_t rawtime2 = ph->time.val_usec;
    struct tm  ts;
    //struct tm  ts2;
    char buf[80];
    //char buf2[80];

    // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts);
    //printf("%s\n\n", buf);

    printf("\n\n<Packet %d> \nLocal Time: %s.%08d\nCaptured Packet Length: %u bytes,   Actual Packet Length: %u bytes\n",
        packetCount, buf, ph->time.val_usec, ph->caplen, ph->len);
}

void showMac(Mac mac) {
    int s, d;//index
    //mac_src
    printf("SRC MAC address: ");
    for (s = 0; s < MAC_ADDR - 1; s++)
        printf("%02x:", mac.MAC_SRC[s]);
    printf("%02x ->  ", mac.MAC_SRC[s]);

    //mac_dst
    printf("DST MAC address: ");
    for (d = 0; d < MAC_ADDR - 1; d++)
        printf("%02x:", mac.MAC_DST[d]);
    printf("%02x\n", mac.MAC_DST[d]);
}

void showIPaddr(IP ip) {
    //src_ip 4byte
    int s, d;
    printf("SRC IP address : ");
    for (s = 0; s < 3; s++)
        printf("%u.", ip.src_ip[s]);
    printf("%u ->  ", ip.src_ip[s]);

    //dst_ip 4byte
    printf("DST IP address : ");
    for (d = 0; d < 3; d++)
        printf("%u.", ip.dst_ip[d]);
    printf("%u\n", ip.dst_ip[d]);
}

int ver_hlen(unsigned char ver_hlen) {
    printf("Ver: %x,  ", ver_hlen >> 4);
    unsigned char tmp = ver_hlen << 4;//하위 4비트를 상위 4비트로 올렸다가
    printf("HLEN in header: %d byte\n", (tmp >> 4) * 4);//상위 4비트를 다시 하위 4비트로 내림 0000xxxx
    return ((tmp >> 4) * 4);
}

int showIP(IP ip) {

    //showIPaddr(ip);//IP address
    printf("Total LEN in IP header: %u byte,  ", ntohs(ip.tot)); //Total Length
    //printf(" TTL: %d\n", ip.ttl); //Time to Live
    ip_hlen =ver_hlen(ip.ver_hlen);//Version and HLEN
    //printf("Id: %d,   ", ntohs(ip.id)); //Identification
    //Flag
    /*if (DF(ip.frag))
        printf("DF=1,   ");
    else {
        if (MF(ip.frag) == 0)
            printf("DF=0 and MF=0,   ");
        else
            printf("DF=0 and MF=1,   ");
    }
    printf("Fragment Offset: %d\n", 8 * (ntohs(ip.frag) & 0x1fff));*/

    int transport=0;

    //Protocol
    switch (ip.protocol) {
    case 1: 
        printf("Protocol: ICMP. "); 
        break;
    case 2: 
        printf("Protocol: IGMP. "); 
        break;
    case 6: 
        printf("Protocol: TCP. "); 
        transport = 1;
        break;
    case 17: 
        printf("Protocol: UDP. "); 
        transport = 2;
        break;
    case 89: 
        printf("Protocol: OSPF. "); 
        break;
    default: 
        printf("This protocol is not supported. "); 
        break;
    }
    return transport; //to determine which function to execute between showTCP and showUDP
}
void flag_check(unsigned short len_flag) {
    //urg,ack,psh,rst,syn,fin
    int uaprsf[6];
    unsigned short tmp = (ntohs(len_flag)) & 0x3F;//하위 6bit만 activated
    for (int i = 0; i < 6; i++) {
        if (tmp & (int)pow(2, 5 - i))
            uaprsf[i] = 1;
        else
            uaprsf[i] = 0;
    }
    puts("-----------------------\nTCP FLAG CHECK\n");
    printf("URG : %d\n", uaprsf[0]);
    printf("ACK : %d\n", uaprsf[1]);
    printf("PSH : %d\n", uaprsf[2]);
    printf("RST : %d\n", uaprsf[3]);
    printf("SYN : %d\n", uaprsf[4]);
    printf("FIN : %d\n", uaprsf[5]);
    /*
    uaprsf[0] = URG
    uaprsf[1] = ACK
    uaprsf[2] = PSH
    uaprsf[3] = RST
    uaprsf[4] = SYN
    uaprsf[5] = FIN
    */
 }

void showTCP(TCP tcp, unsigned int trsp_len) {
    /*
    unsigned short src_port;
    unsigned short dst_port;
    unsigned long seq_num;
    unsigned long ack_num;
    unsigned short len_flag;//hlen(4)+reserved(6)+flag(6)
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;
    */
    unsigned int real_hlen = 4 * (((ntohs(tcp.len_flag)) & 0xF000) >> 12);
    puts("\n-----------------------\n<TCP PARSING START>");
    printf("SRC Port num : %d  DST Port num : %u\n", ntohs(tcp.src_port), ntohs(tcp.dst_port));
    printf("Starting SEQ num : %u\n", ntohl(tcp.seq_num));
    if(trsp_len - real_hlen==0)
        printf("Ending SEQ num : %u\n",ntohl(tcp.seq_num));
    else
        printf("Ending SEQ num : %u\n",ntohl(tcp.seq_num)+trsp_len-real_hlen-1);
    //trsp_len-real_hlen = tcp - tcp header(fixed + option) = tcp payload

    printf("Acknowledgement number : %u\n", ntohl(tcp.ack_num));
    printf("TCP payload size : %u\n", trsp_len-real_hlen);
    printf("TCP Header len : %d\n", real_hlen);
    printf("Window size : %u\n",ntohs(tcp.window));
    flag_check(tcp.len_flag);

    if (trsp_len - real_hlen > max_tcp)
        max_tcp = trsp_len - real_hlen;

    if (real_hlen - 20>0) {
        //find TCP option
        showOption(tcp.option,real_hlen);
    }else
        printf("TCP option does not exist\n");

}

void showUDP(UDP udp, unsigned int trsp_len) {
    /*
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short totlen;
    unsigned short checksum;
    */
    puts("\n-----------------------\n<UDP PARSING START>");
    printf("SRC Port num : %d   DST Port num : %d\n", ntohs(udp.src_port), ntohs(udp.dst_port));
    printf("UDP payload : %d\n", ntohs(udp.totlen)-8);

    if (ntohs(udp.totlen) - 8 > max_udp)
        max_udp = ntohs(udp.totlen) - 8;
}

void showOption(unsigned char* option,unsigned int real_hlen) {
    unsigned char type;
    unsigned char len;
    unsigned short mss;
    unsigned char shift_cnt;
    puts("-----------------------\nTCP OPTION CHECK\n");
    int index = 1;
    //real_hlen-20 = option length
    //printf("option : %x\n", option[]);
   for (int i = 0; i < real_hlen-20; i++) {
       if (option[i] == 0 || option[i] == 1) {
           printf("nop \n");
           continue;
       }
       else if (option[i] == 2) {//mss type2
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : MSS\n");
           printf("Len : %u\n", option[i]);
           mss = (256 * option[i + 1]) + option[i + 2];//1byte씩 읽으니까 endian은 상관없는데, 단위가 달라져서 16^2 해줘야 함
           printf("MSS size : %u\n", mss);
           i = i + 2;
       }
       else if (option[i] == 3) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : Window scale factor\n");
           printf("Len : %u\n", option[i]);
           i++;
           printf("Shift Count : %u\n", option[i]);
           i++;
       }
       else if (option[i] == 4) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : SACK Permitted\n");
           printf("Len : %u\n", option[i]);
       }
       else if (option[i] == 5) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : SACK Data\n");
           printf("Len : %u\n", option[i]);
           i++;
           printf("Left edge : %u\n", option[i]);
       }
       else if (option[i] == 8) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : Timestamp\n");
           printf("Len : %u\n", option[i++]);
           double tmstmp = 0;
           for (int ii = 0; ii < 8; ii++) {
               tmstmp += pow(256, 7 - ii) * option[i++];
           }
           printf("Timestamp : %lf\n", tmstmp);
       }
     
       puts("");
    }
}
//gkgk

/*
else if (option[i] == 5) {
printf("<OPTION %d>\n", index++);
i++;
printf("Type : SACK Permitted\n");
len = option[i];
//unsigned long
printf("Len : %u\n", option[i]);
       }
*/
