#include "custom_header.h"

int main()
{
    pcap_t *handle;         /* The actual packet */
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;

    if(pcap_findalldevs(&device,errbuf)==-1)
    {
        fprintf(stderr,"findalldevs error :%s\n",errbuf);
        return(2);
    }
    findDevice(device);

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return(2);
    }

    while(pcap_next_ex(handle, &header,&packet) >= 0)
    {
        packet_ethernet_header(packet);
    }

    pcap_close(handle);
    return(0);
}
