#ifndef DNS_REQUEST_H
#define DNS_REQUEST_H

// Include declaration ----------------------------------------------------
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
// ------------------------------------------------------------------------

// Define declaration ----------------------------------------------------
#define MAX_DNS_STRING_SIZE 256 // max dns string length
// ------------------------------------------------------------------------

// Struct declaration -----------------------------------------------------
typedef struct dns_packet
{
    unsigned short identification;
    unsigned char qr_op_aa_tc_rd;
    unsigned char ra_z_ad_cd_rcode;
    unsigned short question;
    unsigned short answer;
    unsigned short authority;
    unsigned short additional;
} dns_packet;

typedef struct dns_answer
{
    char name[MAX_DNS_STRING_SIZE];     // Domain name to which this resource record pertains
    unsigned short type;                // Type of the resource record
    unsigned short tClass;              // Class of the resource record
    int ttl;                            // Time to live for this resource record
    unsigned short rdlength;            // Length of the resource data field
    char rdata[MAX_DNS_STRING_SIZE];    // Resource data
} dns_answer;
// ------------------------------------------------------------------------

// Function declaration ----------------------------------------------------
int getRandomInRange(int min, int max);
void dns_string(const char *string, unsigned char result[], size_t *result_len);
// ------------------------------------------------------------------------

#endif // DNS_REQUEST_H