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
typedef struct pcapHeader {//�뾵��
    int magic;
    short major;
    short minor;
    int time_zone;
    int time_stamp;
    int snap_len;
    int link_type;
}pcap_H;

typedef struct Timeval_ {//�ð�
    long val_sec;
    long val_usec;
}Timeval;

typedef struct pktHeader_ {//�ð�+packet length
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

typedef struct UDP {//���� 16bit
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
void showApp(unsigned short portnum);

//����
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
    //pcap�� ������� �κ�(24byte) ���� -> �� ��Ŷ�� TCP ���(MAC, Type) �б�
    pcap_H noUse;
    fread(&noUse, sizeof(pcap_H), 1, fp);
    Parse(fp);//ip
}

void Parse(FILE* fp) {
    pkt_H* ph = packetHeader;
    //fp�� ���� ������ �б� 

    while (feof(fp) == 0) {
        if ((fread(ph, sizeof(pkt_H), 1, fp) != 1))
            break;//pkt_H -> caplen, len(actual packet len) ���� ���� <- ����
        if (packetCount == MAX_PACKET)
            break;

        //��Ŷ�� ���� �ִ� ��� 
        showFileHeader(ph); //time, caplen, actual len ���
        Mac mac;
        fread(&mac, sizeof(mac), 1, fp); //mac �а�,
        //showMac(mac);//mac ���
        char tmpIP[65536];//ip packet�� �ִ� ũ��
        char tmpTransport[65536];//tcp,udp packet�� �ִ� ũ��
        //caplen = ���� packet�� ũ��
        //caplen-(mac address and type which are 14 bytes) = ���� IP������ ũ��
        fread(tmpIP, ph->caplen - 14, 1, fp);
        IP* ip = (IP*)tmpIP; //���� IP header�� ���� ���� : ip
        int tcp_udp = showIP(*ip);//ip���

        int ii = 0;
        for (int i = ip_hlen; i < ph->caplen; i++) {
            tmpTransport[ii] = tmpIP[i];
            ii++;
            /*
            tmpIP���� ip header�� ���� data(tcp header + payload)�鵵 �������
            �׷��ϱ�, tmpTCP�� ip header�� hlen��ŭ ����, �� ������ �����͵��� �����ؾ���. 
            �׷��� 65536 byte �� ���ϰ�, ip header ��������� caplen���� �Űܴ�´�. 
            ++ ip_hlen�� ���������� �����ؼ� showIP �Լ� ���Ŀ�, ip_hlen�� ���� ip����� ũ��(%d)�� ����Ǿ� �ֵ���!
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
    printf("\nMAX_TCP_SIZE : %d\nMAX_UDP_SIZE : %d\n", max_tcp,max_udp);
}



void showFileHeader(pkt_H* ph) {
    packetCount++; //<-����

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
    unsigned char tmp = ver_hlen << 4;//���� 4��Ʈ�� ���� 4��Ʈ�� �÷ȴٰ�
    printf("HLEN in header: %d byte\n", (tmp >> 4) * 4);//���� 4��Ʈ�� �ٽ� ���� 4��Ʈ�� ���� 0000xxxx
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
    unsigned short tmp = (ntohs(len_flag)) & 0x3F;//���� 6bit�� activated
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
    puts("\n-----------------------\n<TCP PARSING>");
    printf("SRC Port num : %d  DST Port num : %u\n", ntohs(tcp.src_port), ntohs(tcp.dst_port));
    printf("SRC Port : ");
    showApp(ntohs(tcp.src_port));
    printf("\nDST port : ");
    showApp(ntohs(tcp.dst_port));
    puts("");
    printf("Starting SEQ num : %u\n", ntohl(tcp.seq_num));
    if(trsp_len - real_hlen==0)
        printf("Ending SEQ num : %u\n",ntohl(tcp.seq_num));
    else
        printf("Ending SEQ num : %u\n",ntohl(tcp.seq_num)+trsp_len-real_hlen-1);
    //trsp_len-real_hlen = tcp - tcp header(fixed + option) = tcp payload

    printf("Acknowledgement number : %u\n", ntohl(tcp.ack_num));
    printf("TCP payload size : %u bytes\n", trsp_len-real_hlen);
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
    puts("\n-----------------------\n<UDP PARSING>");
    printf("SRC Port num : %d   DST Port num : %d\n", ntohs(udp.src_port), ntohs(udp.dst_port));
    printf("SRC Port : ");
    showApp(ntohs(udp.src_port));
    printf("\nDST port : ");
    showApp(ntohs(udp.dst_port));
    puts("");
    printf("UDP payload : %d bytes\n", ntohs(udp.totlen)-8);

    if (ntohs(udp.totlen) - 8 > max_udp)
        max_udp = ntohs(udp.totlen) - 8;
}

void showOption(unsigned char* option,unsigned int real_hlen) {
    unsigned short mss;
    puts("-----------------------\nTCP OPTION CHECK\n");
    int index = 1;
    unsigned int LE = 0 , RE = 0;
    //real_hlen-20 = option length
    //printf("option : %x\n", option[]);
   for (int i = 0; i < real_hlen-20; i++) {
       if (option[i] == 0 || option[i] == 1) {
           printf("<OPTION %d>\n", index++);
           printf("No Operation\n\n");
       }
       else if (option[i] == 2) {//mss type2
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : MSS\n");
           printf("Len : %u\n", option[i]);
           mss = (256 * option[i + 1]) + option[i + 2];//1byte�� �����ϱ� endian�� ������µ�, ������ �޶����� 16^2 ����� ��
           printf("MSS size : %u\n\n", mss);
           i = i + 1;
       }
       else if (option[i] == 3) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : Window scale factor\n");
           printf("Len : %u\n", option[i]);
           i++;
           printf("Shift Count : %u\n\n", option[i]);
       }
       else if (option[i] == 4) {
           printf("<OPTION %d>\n", index++);
           printf("Type : SACK Permitted\n");
           i++;
           printf("Len : %u\n\n", option[i]);
       }
       else if (option[i] == 5) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : SACK Data\n");
           printf("Len : %u\n", option[i]);
           i++;
           for (int ii = 0; ii < 4; ii++) {
               LE += pow(256, 3 - ii) * option[i++];
           }
           printf("Left edge : %u\n", LE);
           for (int ii = 0; ii < 4; ii++) {
               RE += pow(256, 3 - ii) * option[i++];
           }
           printf("Right edge : %u\n\n", RE);
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
           printf("Timestamp : %lf\n\n", tmstmp);
           i = i - 1;
       }
       else if (option[i] ==28) {
           printf("<OPTION %d>\n", index++);
           i++;
           printf("Type : User Timeout\n");
           printf("Len : %u\n", option[i++]);
           printf("User Timeout : %u\n\n", 256 * option[i] + option[i + 1]);
       }
       //tcp-AO ���� ������
     
    }
}

void showApp(unsigned short portnum) {
    switch (portnum) {
    case 1:
        printf("TCPMUX");
        break;
    case 7:
        printf("ECHO");
        break;
    case 9:
        printf("DISCARD");
        break;
    case 13:
        printf("DAYTIME");
        break;
    case 17:
        printf("QOTD");
        break;
    case 19:
        printf("CHARGEN");
        break;
    case 20:
        printf("FTP(Data port)");
        break;
    case 21:
        printf("FTP(Control port)");
        break;
    case 22:
        printf("SSH");
        break;
    case 23:
        printf("TELNET");
        break;
    case 25:
        printf("SMTP");
        break;
    case 37:
        printf("TIME");
        break;
    case 49:
        printf("TACACS");
        break;
    case 53:
        printf("DNS");
        break;
    case 67:
        printf("BOOTP or DHCP");
        break;
    case 69:
        printf("TFTP");
        break;
    case 70:
        printf("Gopher");
        break;
    case 79:
        printf("Finger");
        break;
    case 80:
        printf("HTTP");
        break;
    case 88:
        printf("KERBEROS");
        break;
    case 109:
        printf("POP2");
        break;
    case 110:
        printf("POP3");
        break;
    case 113:
        printf("IDENT");
        break;
    case 119:
        printf("NNTP");
        break;
    case 123:
        printf("NTP");
        break;
    case 139:
        printf("NetBIOS");
        break;
    case 143:
        printf("IMAP4");
        break;
    case 161:
        printf("SNMP");
        break;
    case 179:
        printf("BGP");
        break;
    case 194:
        printf("IRC");
        break;
    case 389:
        printf("LDAP");
        break;
    case 443:
        printf("HTTPS (HTTP over SSL)");
        break;
    case 445:
        printf("Microsoft-DS");
        break;
    case 465:
        printf("SSL over SMTP");
        break;
    case 514:
        printf("syslog");
        break;
    case 540:
        printf("UUCP");
        break;
    case 542:
        printf("Commerce Applications");
        break;
    case 587:
        printf("SMTP");
        break;
    case 591:
        printf("FileMaker");
        break;
    case 636:
        printf("LDAP over SSL");
        break;
    case 873:
        printf("rsync");
        break;
    case 981:
        printf("SofaWare Technologies Checkpoint Firewall-1");
        break;
    case 993:
        printf("IMAP4 over SSL");
        break;
    case 995:
        printf("POP3 over SSL");
        break;
    default:
        printf("Unknown Application");
        break;
    }
}