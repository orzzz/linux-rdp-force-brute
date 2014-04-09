#include <stdio.h> //printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>    //hostend
#include <arpa/inet.h>
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#define  msg(fmt,arg...) printf(fmt,##arg);fflush(stdout)
 
const char *logFileName = "Result.txt";
int log_fd = 0;  // for log
int bIsLogRet = 0 ;//is log scan result
uint32_t g_bind_ip = 0; // 绑定的本地ip
uint8_t g_port_list[0xFFFF] = {0}; //要扫描的端口相应的位会被置1
volatile int g_IsTimeToShutDown = 0;
 
enum IpSingType
{
    IP_TYPE_RANGE,
    IP_TYPE_SINGLE
};
 
typedef struct _IPSting
{
    enum IpSingType type;
    uint32_t start_ip;
    uint32_t end_ip;
}IPString;
 
IPString *g_ScanIpList = NULL;
uint32_t  g_IpCount = 0;
 
#pragma pack(push,1)
 
typedef struct _ip_header
{
    unsigned char  h_lenver; //4位首部长度+4位IP版本号
    unsigned char  tos; //8位服务类型TOS
    unsigned short total_len; //16位总长度（字节）
    unsigned short ident; //16位标识
    unsigned short frag_and_flags; //3位标志位
    unsigned char  ttl; //8位生存时间 TTL
    unsigned char  proto; //8位协议 (TCP, UDP 或其他)
    unsigned short checksum; //16位IP首部校验和
    uint32_t   sourceIP; //32位源IP地址
    uint32_t   destIP; //32位目的IP地址
}IP_HEADER;
 
typedef struct _tcp_header //定义TCP首部
{
    unsigned short th_sport; //16位源端口
    unsigned short th_dport; //16位目的端口
    uint32_t   th_seq; //32位序列号
    uint32_t   th_ack; //32位确认号
    unsigned char  th_lenres; //4位首部长度/6位保留字
    unsigned char  th_flag; //6位标志位
    unsigned short th_win; //16位窗口大小
    unsigned short th_sum; //16位校验和
    unsigned short th_urp; //16位紧急数据偏移量
}TCP_HEADER;
 
typedef struct _psd_header //定义TCP伪首部
{
    unsigned long saddr; //源地址
    unsigned long daddr; //目的地址
    char mbz;
    char ptcl; //协议类型
    unsigned short tcpl; //TCP长度
}PSD_HEADER;
 
#pragma pack(pop)
 
/*
Get ip from domain name
*/
uint32_t hostname_to_ip(char * hostname)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    //msg("%s:%s\n",__func__,hostname);
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        //herror("gethostbyname");
        //use inet_ntoa
        return inet_addr(hostname);
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
 
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        return (*addr_list[i]).s_addr;
        //return inet_ntoa(*addr_list[i]) ;
    }
    return 0;
}
 
unsigned short checkSum(void * buffer, int size)
{
    unsigned long cksum=0;
    while (size >1) {
        cksum += *(unsigned short *)buffer;
        size -= sizeof(unsigned short);
        buffer = (char *)buffer + sizeof(unsigned short);
    }
    if (size) cksum += *(unsigned char*) buffer;
    cksum = (cksum >> 16) + (cksum&0xffff);
    cksum += (cksum >> 16);
    return (unsigned short) (~cksum);
}
 
int    buildSynPacket(char * buf, u_long saddr, u_long sport, u_long daddr, u_long dport)
{
    int    len = 0;
    IP_HEADER ip_header;
    TCP_HEADER tcp_header;
    PSD_HEADER psd_header;
    //填充IP首部
    ip_header.h_lenver=(4<<4 | sizeof(ip_header)/sizeof(unsigned long));
    //高四位IP版本号，低四位首部长度
    ip_header.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16位总长度（字节）
    ip_header.ident=1; //16位标识
    ip_header.frag_and_flags = 0; //3位标志位
    ip_header.ttl = 128; //8位生存时间TTL
    ip_header.proto = IPPROTO_TCP; //8位协议(TCP,UDP…)
    ip_header.checksum = 0; //16位IP首部校验和
    ip_header.sourceIP = saddr; //32位源IP地址
    ip_header.destIP = daddr; //32位目的IP地址
 
    //填充TCP首部
    tcp_header.th_sport = sport; //源端口号
    tcp_header.th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP长度和保留位
    tcp_header.th_win = htons(0x4000);
 
    //填充TCP伪首部（用于计算校验和，并不真正发送）
    psd_header.saddr=ip_header.sourceIP;
    psd_header.daddr=ip_header.destIP;
    psd_header.mbz=0;
    psd_header.ptcl=IPPROTO_TCP;
    psd_header.tcpl=htons(sizeof(tcp_header));
 
    tcp_header.th_dport = dport; //目的端口号
    tcp_header.th_ack=0; //ACK序列号置为0
    tcp_header.th_flag=2; //SYN 标志
    tcp_header.th_seq = sport -1; //SYN序列号随机
    tcp_header.th_urp=0; //偏移
    tcp_header.th_sum=0; //校验和
    //计算TCP校验和，计算校验和时需要包括TCP pseudo header
    memcpy(buf,&psd_header,sizeof(psd_header));
    memcpy(buf+sizeof(psd_header),&tcp_header,sizeof(tcp_header));
    tcp_header.th_sum=checkSum(buf,sizeof(psd_header)+sizeof(tcp_header));
 
    //计算IP校验和
    memcpy(buf,&ip_header,sizeof(ip_header));
    memcpy(buf+sizeof(ip_header),&tcp_header,sizeof(tcp_header));
    memset(buf+sizeof(ip_header)+sizeof(tcp_header),0,4);
    len=sizeof(ip_header)+sizeof(tcp_header);
    ip_header.checksum=checkSum(buf,len);
 
    //填充发送缓冲区
    memcpy(buf,&ip_header,sizeof(ip_header));
 
    return len;
}
 
const char *TakeOutStringByChar(const char *Source,char *Dest, int buflen, char ch)
{
    int i;
 
    if(Source == NULL)
        return NULL;
 
    const char *p = strchr(Source, ch);
    while(*Source == ' ')
        Source++;
    for(i=0; i<buflen && *(Source+i) && *(Source+i) != ch; i++)
    {
        Dest[i] = *(Source+i);
    }
    if(i == 0)
        return NULL;
    else
        Dest[i] = '\0';
 
    const char *lpret = p ? p+1 : Source+i;
 
    while(Dest[i-1] == ' ' && i>0)
        Dest[i---1] = '\0';
 
    return lpret;
}
 
void InsertIntoIpList(enum IpSingType type,uint32_t start_ip,uint32_t end_ip)
{
//    msg("%s:%x %x\n",__func__,start_ip,end_ip);
    if(!g_ScanIpList)
    {
        g_ScanIpList = (IPString *)malloc(sizeof(IPString));
        g_ScanIpList->end_ip = end_ip;
        g_ScanIpList->start_ip = start_ip;
        g_ScanIpList->type = type;
        ++g_IpCount ;
        return ;
    }
    else
    {
        IPString *pTmp = (IPString *)malloc((g_IpCount + 1) * sizeof(IPString));
        memcpy(pTmp,g_ScanIpList,g_IpCount * sizeof(IPString));
        free(g_ScanIpList);
        g_ScanIpList = pTmp;
        g_ScanIpList[g_IpCount].end_ip = end_ip;
        g_ScanIpList[g_IpCount].start_ip = start_ip;
        g_ScanIpList[g_IpCount].type = type;
        ++g_IpCount;
        return;
    }
};
 
void DestoryIpList()
{
    free(g_ScanIpList);
    g_ScanIpList = NULL;
}
 
/*
典型的用法
 
  uint32_t start = inet_addr("192.168.122.1");
  uint32_t end = inet_addr("192.168.123.122");
  uint32_t ip = start;
  do
  {
        msg("%s\n",inet_ntoa(*(struct in_addr *)&ip));
 
          } while ((ip = GetNextIpInRange(ip,end)));
*/
uint32_t GetNextIpInRange(uint32_t start,uint32_t end)
{
    uint32_t pos = start;
    pos = htonl(start )+1;
    if(pos > htonl(end))
    {
        return 0;
    }
    pos = htonl(pos);
    return pos;
}
 
int  ParseIpString(const char *IpString)
{
    const char *p = IpString;
    char *slash = NULL;
    char buff[256];
    struct hostent * hostInfo ;
 
    while((p = TakeOutStringByChar(p,buff,256,',')))
    {
        char startIpStr[256]={0};
        uint32_t start,end,range,submask;
        start = end = range = submask = 0;
        enum IpSingType type;
        //msg("%s  \n",buff);
        if((slash = strchr(buff,'/'))) //12.12.12.12/24
        {
            strncpy(startIpStr, buff, slash - buff );
            int bit = atoi(slash+1);
            range = 0xFFFFFFFF >> bit;
            submask = 0xFFFFFFFF << (32 - bit);
            uint32_t ip = hostname_to_ip(startIpStr);
            if(!ip)
                continue;
            start = (ip & ntohl(submask)) + ntohl(1);
            end = (ip & ntohl(submask)) + ntohl(range-1);
            type = IP_TYPE_RANGE;
        }
        else if((slash = strchr(buff,'-')))  //12.12.12.12 - 12.12.12.122
        {
            strncpy(startIpStr, buff, slash - buff );
            start = hostname_to_ip(startIpStr);
            end = hostname_to_ip(slash+1);
            type = IP_TYPE_RANGE;
 
        }else //12.12.12.12
        {
            start = hostname_to_ip(buff);
            end = 0xFFFFFFFF;
            type = IP_TYPE_SINGLE;
        }
        if ((start || end) && (htonl(start) < htonl(end)))
        {
            InsertIntoIpList(type,start,end);
            //char endIpStr[256];
            //strcpy(endIpStr, inet_ntoa(*(struct in_addr *)&end));
            //strcpy(startIpStr, inet_ntoa(*(struct in_addr*)&start));
            //msg("start : %s end :%s \n",startIpStr,endIpStr);
        }
    }
}
 
void  GetNextScanIp(int (*callback)(uint32_t,void *),void *lparam)
{
    uint32_t idx;
    if(!g_ScanIpList)
    {
        msg("%s Ip list not init\n",__func__);
        return ;
    }
    for (idx = 0 ;idx < g_IpCount;idx ++)
    {
        switch(g_ScanIpList[idx].type)
        {
        case IP_TYPE_RANGE:
            {
                //msg("%s:%x %x\n",__func__,g_ScanIpList[idx].start_ip,g_ScanIpList[idx].end_ip);
                uint32_t ip = g_ScanIpList[idx].start_ip;
                do
                {
                    callback(ip,lparam);
                } while ((ip = GetNextIpInRange(ip,g_ScanIpList[idx].end_ip)));
            }
            break;
        case IP_TYPE_SINGLE:
            {
                callback(g_ScanIpList[idx].start_ip,lparam);
            }
            break;
        default:
            msg("%s:%s",__func__,"unknow ip type \n");
            break;
        }
    }
}
 
void ParsePortString(const char *ScanPortString)
{
    const char *p = ScanPortString;
    char buff[256];
    int idx;
    while((p = TakeOutStringByChar(p,buff,256,',')))
    {
        uint16_t start,end;
        char *slash = NULL;
        char port[64] = {0};
        if((slash = strchr(buff,'-')))  //122-1111
        {
            strncpy(port,buff, slash - buff );
            start = atoi(port);
            end = atoi(slash + 1);
            if(end < start)
            {
                continue;
            }
            for (idx = start;idx<=end;idx++)
            {
                g_port_list[idx] = 1;
            }
        }else
        {
            start = atoi(buff);
            g_port_list[start] = 1;
        }
    }
}
 
uint32_t  GetScanPortCount()
{
    int idx = 0 ;
    uint32_t count = 0 ;
    for (idx = 0 ;idx < 0xFFFF;idx++)
    {
        if(g_port_list[idx])
            ++count;
    }
    return count;
}
 
int help(char * app) //argc 3 4
{
    printf("Usage:   %s [Ip String] Ports [/Save]\n", app);
    printf("Example: %s 12.12.12.12-12.12.12.254 80\n", app);
    printf("Example: %s 12.12.12.12 1-65535\n", app);
    printf("Example: %s 12.12.12.12/24 1-65535\n", app);
    printf("Example: %s 12.12.12.12-12.12.12.254 21,80,3389\n", app);
    return printf("Example: %s 12.12.12.12,12.12.12.122 21,80,3389-22233  /Save\n", app);
}
 
/*
Method to sniff incoming packets and look for Ack replies
*/
void * receive_ack( void *ptr )
{
    //Start the sniffer thing
    start_sniffer();
}
 
void process_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    char log_buff[256];
    int len = 0;
    IP_HEADER *iphdr = (IP_HEADER *)buffer;
    TCP_HEADER *tcphdr = NULL;
    struct sockaddr_in source,dest;
 
    if(iphdr->proto = IPPROTO_TCP)
    {
        /* retireve the position of the tcp header */
        int ip_len = (iphdr->h_lenver & 0xf) * 4;
        tcphdr = (TCP_HEADER *) (buffer + ip_len);
        if(tcphdr->th_flag == 18)  //ACK+SYN
        {
            len = sprintf(log_buff,"%-16s%-8uOPEN                                           \n",inet_ntoa(*(struct in_addr *)&iphdr->sourceIP),ntohs(tcphdr->th_sport));
            if(bIsLogRet)
            {
                write(log_fd,log_buff,len);
            }
            msg("%s",log_buff);
        }
    }
}
 
int start_sniffer()
{
    int sock_raw = 0; // raw socket for sniff
    int saddr_size , data_size;
    struct sockaddr saddr;
 
    unsigned char buffer[65536];// = (unsigned char *)malloc(65536); //Its Big!
 
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
 
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        fflush(stdout);
        return 1;
    }
 
    saddr_size = sizeof saddr;
    while(!g_IsTimeToShutDown)
    {
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            msg("%s","Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        process_packet(buffer , data_size);
    }
    close(sock_raw);
//    msg("%s","Sniffer finished.");
    return 0;
}
 
uint32_t get_local_ip (uint32_t ip)
{
    char buffer[100];
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
    int dns_port = 53;
    int err;
    struct sockaddr_in serv;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    //msg("%s:%s  \n",__func__,inet_ntoa(*(struct in_addr *)&ip));
    memset( &serv, 0, sizeof(serv));
    memset( &name, 0, sizeof(name));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = ip;//inet_addr(HostName);
    //memcpy(&serv.sin_addr.s_addr,&ip,4);
    serv.sin_port = htons( dns_port );
    err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    //const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    if(-1 == err)
    {
        msg("%s:%s",__func__,"getsockname failed\n");
    }
    close(sock);
    return name.sin_addr.s_addr;
}
 
int ip_callback(uint32_t ip,void *lparam)
{
    static uint32_t seed = 0x2b;
    uint32_t idx = 0;
    int len = 0;
    int s  = (int)lparam;
    struct sockaddr_in addr;
    char buff[0x100];
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    if(!g_bind_ip)
    {
        g_bind_ip = get_local_ip(ip);
        msg("bind on ip : %s \n",inet_ntoa(*(struct in_addr *)&g_bind_ip));
    }
    for (idx = 0 ; idx < 0xFFFF;idx ++)
    {
        if(g_port_list[idx])
        {
            addr.sin_port = htons(idx);
            msg("scanning %16s:%u\r",inet_ntoa(*(struct in_addr *)&ip),idx);
            srandom(seed++);
            len = buildSynPacket(buff,g_bind_ip,htons(random() % 0xFFFF),ip,addr.sin_port);
            if ( sendto (s,buff,len, 0 , (struct sockaddr *) &addr, sizeof (addr)) < 0)
            {
                 printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                return 0;
            }
        }
    }
    return 1;
}
 
int main(int argc, char *argv[])
{
    int s;
    uint32_t ScanPortCount = 0;
    msg("%s","s syn port scanner\nBY:sincoder\nBlog:www.sincoder.com\n");
    if(argc < 3 )
    {
        help(argv[0]);
        return -1;
    }
    ParseIpString(argv[1]);
    ParsePortString(argv[2]);
    ScanPortCount = GetScanPortCount();
    if(!ScanPortCount)
    {
        msg("%s","No Ports !!\n");
        return -1;
    }else
    {
        msg("About to scan %u ports\n",ScanPortCount);
    }
    if(argc == 4)
    {
        bIsLogRet = 1;
        log_fd = open(logFileName,O_RDWR|O_APPEND|O_CREAT,S_IRUSR|S_IWUSR);
        if(log_fd == -1)
        {
            msg("Can not create log file .\n");
        }
    }
    //Create a raw socket
    s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if(s < 0)
    {
        msg("%s","Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        return -1;
    }
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    msg("%s","Starting sniffer thread...\n");
    pthread_t sniffer_thread;
    g_IsTimeToShutDown = 0;
    if( pthread_create( &sniffer_thread , NULL ,  receive_ack , NULL) < 0)
    {
        msg("%s","Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        goto clean;
    }
    GetNextScanIp(ip_callback,(void *)s);
    sleep(2);
    g_IsTimeToShutDown = 1;
    ip_callback(g_bind_ip,(void *)s); //send a packet to myself ,let me exit ^_^
    msg("%s","scan over!!                             \n");
    pthread_join( sniffer_thread , NULL);
clean:
    DestoryIpList();
    if(bIsLogRet)
        close(log_fd);
    close(s);
    return 0;
}
