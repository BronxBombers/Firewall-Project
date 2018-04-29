/// \file filter.c
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Chris Dickens (RIT CS)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "filter.h"
#include "pktUtility.h"

/// maximum line length of a configuration file
#define MAX_LINE_LEN  256

#define HEADER_LENGTH 20


/// The type used to hold the configuration settings for a filter
typedef struct FilterConfig_S{
    unsigned int localIpAddr;    ///< the local IP address
    unsigned int localMask;      ///< the address mask
    bool blockInboundEchoReq;    ///< where to block inbound echo
    unsigned int numBlockedInboundTcpPorts;   ///< count of blocked ports
    unsigned int* blockedInboundTcpPorts;     ///< array of blocked ports
    unsigned int numBlockedIpAddresses;       ///< count of blocked addresses
    unsigned int* blockedIpAddresses;         ///< array of blocked addresses
} FilterConfig;


/// Parses the remainder of the string last operated on by strtok 
/// and converts each octet of the ASCII string IP address to an
/// unsigned integer value.
/// @param ipAddr The destination into which to store the octets
/// @pre caller must have first called strtok to set its pointer.
/// @post ipAddr contains the ip address found in the string
static void parse_remainder_of_string_for_ip(unsigned int* ipAddr){
    char* pToken;
    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[0]);
    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[1]);
    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[2]);
    pToken = strtok(NULL, "/");
    sscanf(pToken, "%u", &ipAddr[3]);
}


/// Checks if an IP address is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address that is to be checked
/// @return True if the IP address is to be blocked
static bool block_ip_address(FilterConfig* fltCfg, unsigned int addr){
    unsigned int * IPs = fltCfg->blockedIpAddresses;
    unsigned int numIPs = fltCfg->numBlockedIpAddresses;
    for (unsigned int i = 0; i < numIPs; i++){
        if (IPs[i] == addr){
            return true;
        }
    }
    return false;

}


/// Checks if a TCP port is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port that is to be checked
/// @return True if the TCP port is to be blocked
static bool block_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
    unsigned int * Ports = fltCfg->blockedInboundTcpPorts;
    unsigned int numPorts = fltCfg->numBlockedInboundTcpPorts;
    for (unsigned int i = 0; i < numPorts; i++){
        if (Ports[i] == port){
            return true;
        }
    }
    return false;
}   


/// Checks if a packet is coming into the network from the external world. Uses
/// the localMask in the supplied filter configuration to compare the srcIpAddr
/// and dstIpAddr to the localIpAddr supplied in the filter configuration. If the
/// dstIpAddr is on the same network as the localIpAddr, and the srcIpAddr is not
/// on the same network as the localIpAddr then the packet is inbound.
/// @param fltCfg The filter configuration to use
/// @param srcIpAddr The source IP address of a packet
/// @param dstIpAddr The destination IP address of a packet
static bool packet_is_inbound(FilterConfig* fltCfg, unsigned int srcIpAddr, unsigned int dstIpAddr){
    unsigned int mask = fltCfg->localMask;
    unsigned int destination = dstIpAddr & mask;
    unsigned int source = srcIpAddr & mask;
    unsigned int local = fltCfg->localIpAddr & mask;
    return (destination == local && source != local);
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void add_blocked_ip_address(FilterConfig* fltCfg, unsigned int ipAddr){
    unsigned int numIP = fltCfg->numBlockedIpAddresses;
    unsigned int * configIPs = fltCfg->blockedIpAddresses;
    unsigned int tempArray[numIP];
    for (unsigned int i = 0; i < numIP; i++){
        tempArray[i] = configIPs[i];
    }
    free(configIPs);
    configIPs = malloc(sizeof(unsigned int) * ++numIP);
    for (unsigned int i = 0; i < numIP; i++){
        configIPs[i] = tempArray[i];
    }
    configIPs[numIP-1] = ipAddr;
    fltCfg->numBlockedIpAddresses = numIP;
    fltCfg->blockedIpAddresses = configIPs;
}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void add_blocked_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
    unsigned int numPorts = fltCfg->numBlockedInboundTcpPorts;
    unsigned int * configPorts = fltCfg->blockedInboundTcpPorts;
    unsigned int tempArray[numPorts];
    for (unsigned int i = 0; i < numPorts; i++){
        tempArray[i] = configPorts[i];
    }
    free(configPorts);
    configPorts = malloc(sizeof(unsigned int) * (numPorts+1));
    for (unsigned int i = 0; i < numPorts; i++){
        configPorts[i] = tempArray[i];
    }
    configPorts[numPorts] = port;
    fltCfg->numBlockedInboundTcpPorts++;
    fltCfg->blockedInboundTcpPorts = configPorts;
}


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter create_filter(void){
    FilterConfig* filter = malloc(sizeof(FilterConfig));
    filter->blockInboundEchoReq = false;
    filter->numBlockedInboundTcpPorts = 0;
    filter->blockedInboundTcpPorts = malloc(sizeof(unsigned int));
    filter->numBlockedIpAddresses = 0;
    filter->blockedIpAddresses = malloc(sizeof(unsigned int));
    return (IpPktFilter*)filter; 
}


/// Destroys an instance of a filter by freeing all of the dynamically
/// allocated memory associated with the filter.
/// @param filter The filter that is to be destroyed
void destroy_filter(IpPktFilter filter){
    FilterConfig* fltCfg = filter;
    free(fltCfg->blockedInboundTcpPorts);
    free(fltCfg->blockedIpAddresses);
    free(fltCfg);
}

unsigned int createHexMask(unsigned int mask){
    mask /= 8;
    int newMask = 0;
    for (unsigned int i = 1; i < mask+1; i++){
        newMask += 255 << (i * 8);
    }
    return newMask;
}

/// Configures a filter instance using the specified configuration file.
/// Reads the file line by line and uses strtok, strcmp, and sscanf to 
/// parse each line.  After each line is successfully parsed the result
/// is stored in the filter.  Blank lines are skipped.  When the end of
/// the file is encountered, the file is closed and the function returns.
/// @param filter The filter that is to be configured
/// @param filename The full path/filename of the configuration file that
/// is to be read.
/// @return True when successful
bool configure_filter(IpPktFilter filter, char* filename){
    FilterConfig * f = (FilterConfig*)filter;
    char buf[MAX_LINE_LEN];
    FILE* pFile;
    char* property;
    bool  validConfig = false;
    char local_net[11] = "LOCAL_NET";
    char blockPort[24] = "BLOCK_INBOUND_TCP_PORT";
    char blockIP[15] = "BLOCK_IP_ADDR";
    char blockPing[16] = "BLOCK_PING_REQ";
    unsigned int address[4];
    pFile = fopen(filename, "r"); 
    if(pFile == NULL){
        fprintf(stderr, "ERROR: invalid config file\n");
        return false;
    }
    while (fgets(buf, MAX_LINE_LEN, pFile)){
        property = strtok(buf, ":  \t\r\n\v\f");
        if (property != NULL){
            if (strcmp(property, local_net) == 0){
                validConfig = true;
                parse_remainder_of_string_for_ip(address);
                f->localIpAddr = ConvertIpUIntOctetsToUInt(address);
                char * token = strtok(NULL, "  \t\r\n\v\f");
                f->localMask = createHexMask(strtoul(token, NULL, 10));
            }
            if (strcmp(property, blockPing) == 0){
                f->blockInboundEchoReq = true;
            }
            if (strcmp(property, blockIP) == 0){
                parse_remainder_of_string_for_ip(address);
                add_blocked_ip_address(f, ConvertIpUIntOctetsToUInt(address));
            }
            if (strcmp(property, blockPort) == 0){
                unsigned int arg;
                arg = strtoul(buf + strlen(property) + 1, NULL, 10);
                add_blocked_inbound_tcp_port(f, arg);
            }
        }
    }
    if(validConfig == false){
        fprintf(stderr, "ERROR: configuration file must set LOCAL_NET\n");
    }
    fclose(pFile);
    return validConfig;
}


/// Uses the settings specified by the filter instance to determine
/// if a packet should be allowed or blocked.  The source and
/// destination IP addresses are extracted from each packet and
/// checked using the block_ip_address helper function. The IP protocol
/// is extracted from the packet and if it is ICMP or TCP then 
/// additional processing occurs. This processing blocks inbound packets
/// set to blocked TCP destination ports and inbound ICMP echo requests.
/// @param filter The filter configuration to use
/// @param pkt The packet to exame
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool filter_packet(IpPktFilter filter, unsigned char* pkt){
    unsigned int srcIpAddr = ExtractSrcAddrFromIpHeader(pkt);
    unsigned int dstIpAddr = ExtractDstAddrFromIpHeader(pkt);
    FilterConfig* fltCfg = (FilterConfig*)filter;
    unsigned int protocol = ExtractIpProtocol(pkt);
    if (packet_is_inbound(fltCfg, srcIpAddr, dstIpAddr)){
        if (block_ip_address(fltCfg, srcIpAddr)) return false;
        if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP){
            unsigned int port = ExtractTcpDstPort(pkt);
            if (block_inbound_tcp_port(fltCfg, port)) return false;
        }
        if (protocol == IP_PROTOCOL_ICMP){
            unsigned char type = ExtractIcmpType(pkt);
            if (fltCfg->blockInboundEchoReq && type == ICMP_TYPE_ECHO_REQ) return false;
        }
    }
    return true;
}
/**
void testConfig(FilterConfig * f){
    printf("Local Address: %u\n", f->localIpAddr);
    printf("Local Mask: %u\n", f->localMask);
    printf("Ping Blocked? %s\n", f->blockInboundEchoReq ? "true" : "false");
    for (unsigned int i = 0; i < f->numBlockedIpAddresses; i++){
        printf("Blocked IP Address #%u: %u\n", i, f->blockedIpAddresses[i]);
    }
    for (unsigned int i = 0; i < f->numBlockedInboundTcpPorts; i++){
        printf("Blocked TCP Address #%u: %u\n", i, f->blockedInboundTcpPorts[i]);
    }
}

int main(int argc, char * argv[]){
    FilterConfig * filter = (FilterConfig*)create_filter();
    configure_filter(filter, argv[1]);
    //testConfig(filter);
    unsigned char pkt[20] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};
    printf("Good Packet: %d\n" , isCheckSumGood(pkt));
    unsigned char pkt2[20] = {0x10, 0x00, 0x00, 0x50, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};
    printf("Bad Packet: %d\n", isCheckSumGood(pkt2));
    destroy_filter(filter);
}
**/