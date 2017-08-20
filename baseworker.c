#include "custom_header.h"

int findDevice(pcap_if_t *device)
{
    pcap_if_t *temp_device;
    u_int d=1;
    u_int i;
    u_int choice;

    temp_device = device;
    while(temp_device->next != NULL)
    {
        printf("%d. %s\n",d,temp_device->name);
        temp_device=temp_device->next;
        d++;
    }
    printf("choice device num : ");
    scanf("%u",&choice);
    if(choice < 1 || choice >= d)
    {
        fprintf(stderr,"correct number\n");
        return 2;
    }

    for(i=0;i<d;i++)
        device=device->next;
    return 0;
}

int packet_ethernet_header(const u_char *packet)
{
    int i=0;
    struct ethernet_header *eh;
    u_short ether_type;

    eh = (struct ethernet_header *)packet;
    ether_type = ntohs(eh->ether_Type);

    //assert(ether_type == 0x0800); // arp :0806
    if(ether_type != 0x0800)
        return 2;
    // first, search http port
    if(packet_tcp_header(packet+34)<0)
        return 2;

    printf("Dst MAC Addr : ");
    for (i = 0; i <= 5; i++)
    {
        printf("%02x ", eh->dst_Mac[i]);
    }
    printf("\nSrc MAC Addr : ");
    for (i = 0; i <= 5; i++)
    {
        printf("%02x ", eh->src_Mac[i]);
    }
    printf("\nether_type : %x\n",ether_type);
    packet_ip_header(packet+14);


    return 0;
}

int packet_ip_header(const u_char *packet)
{

    struct ip_header *ih;
    char buffer[20];
    ih=(struct ip_header *)(packet+12);
    printf("src ip : %s\n",inet_ntop(AF_INET,&ih->src_addr,buffer,sizeof(buffer)));
    printf("dst ip : %s\n",inet_ntop(AF_INET,&ih->dst_addr,buffer,sizeof(buffer)));
    printf("=========PACKET DETAIL End========\n");
    return 0;
}

int packet_tcp_header(u_char *packet)
{
    struct tcp_header *th;
    u_short F_srcport;
    u_short F_dstport;
    th = (struct tcp_header *)packet;

    F_srcport = ntohs(th->src_port);
    F_dstport = ntohs(th->dst_port);
    if(F_dstport == 80 || F_srcport == 80)
    {
        printf("\n=========PACKET DETAIL=============\n");
        printf("Src Port Num : %d\n", F_srcport);
        printf("Dst Port Num : %d\n", F_dstport);
    }
    else
        return -1;

    return 0;
}
