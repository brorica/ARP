#ifndef CUSTOM_HEADER_H
#define CUSTOM_HEADER_H

#endif // CUSTOM_HEADER_H

#include <stdio.h>
#include <pcap.h>
#include <assert.h>
#include <arpa/inet.h>

struct ethernet_header
{
    u_char dst_Mac[6];
    u_char src_Mac[6];
    u_short ether_Type;
};\

struct ip_header
{
    struct in_addr src_addr;
    struct in_addr dst_addr;
};

struct tcp_header
{
    u_short src_port; // Source port
    u_short dst_port; // Destination port
};

/* baseworker.c */
int findDevice(pcap_if_t *device);
int packet_ethernet_header(const u_char *packet);
int packet_ip_header(const u_char *packet);
int packet_tcp_header(u_char *packet);

