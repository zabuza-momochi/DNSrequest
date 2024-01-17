// Include declaration ----------------------------------------------------
#include "dns_request.h"
// ------------------------------------------------------------------------

// Function declaration ---------------------------------------------------
int getRandomInRange(int min, int max)
{
    // Seed random number generator with the current time
    srand((unsigned int)time(NULL));

    return min + rand() % (max - min + 1);
}

void dns_string(const char *string, unsigned char result[], size_t *result_len)
{
    size_t total_length = 0;
    size_t offset = 0;

    while (*string != '\0')
    {
        const char *delimiter = strchr(string, '.');
        size_t part_length;

        if (delimiter != NULL)
        {
            part_length = (size_t)(delimiter - string);
        }
        else
        {
            part_length = strlen(string);
        }

        result[offset] = (unsigned char)part_length;
        memcpy(result + offset + 1, string, part_length);
        offset += part_length + 1;

        string += part_length;

        if (*string == '.')
        {
            string++; // Salta il punto
        }

        total_length += part_length + 1;
    }

    result[offset] = '\x00'; // Null terminator
    *result_len = total_length + 1;
}
// ------------------------------------------------------------------------

// Entry point ------------------------------------------------------------
int main(int argc, char *args[])
{
#ifdef _WIN32
    // This part is only required on windows, init the winsock2 dll
    WSADATA wsa_data;

    // Init winsock library on windows
    if (WSAStartup(0x0202, &wsa_data))
    {
        printf("unable to initialize winsock2 \n");
        return -1;
    }
#endif

    // Init packet struct
    dns_packet packet_header;

    // Clear data
    memset(&packet_header, 0, sizeof(packet_header));

    // Generate random identification
    packet_header.identification = htons(getRandomInRange(0, 65535) & 0xFFFF);
    packet_header.identification = htons(3974);

    // Set vars
    unsigned char query = 0;
    unsigned char opcode = 0;
    unsigned char aa = 0;    // not relevant for client
    unsigned char tc = 0;    // not relevant for client
    unsigned char rd = 1;    // recursion desired
    unsigned char ra = 0;    // not relevant for client
    unsigned char rcode = 0; // not relevant for client

    // Aggregate vars to 1 byte
    packet_header.qr_op_aa_tc_rd = (query << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd;
    packet_header.ra_z_ad_cd_rcode = rcode;

    // Set the question field to 1
    packet_header.question = htons(1);   // A type
    packet_header.answer = htons(0);     // filled by server
    packet_header.authority = htons(0);  // filled by server
    packet_header.additional = htons(0); // filled by server

    // Print data
    printf("---------------------------\n");
    printf(">>> Generate random id:\n");
    printf("Identification DEC: %u\n", ntohs(packet_header.identification));
    printf("Identification HEX: 0x%04X\n", ntohs(packet_header.identification));

    printf("---------------------------\n");
    printf(">>> Generate packet header:\n");

    for (size_t i = 0; i < sizeof(packet_header); ++i)
    {
        // Print ASCII char
        if (((unsigned char *)&packet_header)[i] >= 32 && ((unsigned char *)&packet_header)[i] <= 126)
        {
            printf("%c", ((unsigned char *)&packet_header)[i]);
        }
        else
        {
            // Print byte char
            printf("\\x%02X", ((unsigned char *)&packet_header)[i]);
        }
    }
    printf("\n");

    const char *domain = "aiv01.it";                    // Set domain
    unsigned char packet_question[MAX_DNS_STRING_SIZE]; // Init struct
    size_t packet_question_len;                         // Init packet len

    // Generate dns string
    dns_string(domain, packet_question, &packet_question_len);

    // Print DNS converted string
    printf("---------------------------\n");
    printf(">>> Generate DNS String:\n");

    for (size_t i = 0; i < packet_question_len; ++i)
    {
        // Print ASCII char
        if (packet_question[i] >= 32 && packet_question[i] <= 126)
        {
            printf("%c", packet_question[i]);
        }
        else
        {
            // Print byte char
            printf("\\x%02X", packet_question[i]);
        }
    }

    printf("\n");

    unsigned short aType = htons(1); // A type
    unsigned short class = htons(1); // class IN/Internet

    // Add type to packet question
    memcpy(packet_question + packet_question_len, &aType, sizeof(unsigned short));
    packet_question_len += sizeof(unsigned short);

    // Add class to packet question
    memcpy(packet_question + packet_question_len, &class, sizeof(unsigned short));
    packet_question_len += sizeof(unsigned short);

    // Print combined sequence in hexadecimal
    printf("---------------------------\n");
    printf(">>> Generate packet question:\n");
    for (size_t i = 0; i < packet_question_len; ++i)
    {
        // Print ASCII char
        if (packet_question[i] >= 32 && packet_question[i] <= 126)
        {
            printf("%c", packet_question[i]);
        }
        else
        {
            // Print ASCII char
            printf("\\x%02X", packet_question[i]);
        }
    }
    printf("\n");

    // Copy packet_question after the end of packet_header
    memcpy(((unsigned char *)&packet_header) + sizeof(packet_header), packet_question, packet_question_len);

    // Print the combined sequence in hexadecimal
    printf("---------------------------\n");
    printf(">>> Combine packets [header + question]:\n");
    for (size_t i = 0; i < sizeof(packet_header) + packet_question_len; ++i)
    {
        // Print ASCII char
        if (((unsigned char *)&packet_header)[i] >= 32 && ((unsigned char *)&packet_header)[i] <= 126)
        {
            printf("%c", ((unsigned char *)&packet_header)[i]);
        }
        else
        {
            // Print byte char
            printf("\\x%02X", ((unsigned char *)&packet_header)[i]);
        }
    }
    printf("\n");

    // Create a UDP socket
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Check if the socket creation is successful
    if (s < 0)
    {
        printf("Unable to initialize the UDP socket \n");
        return -1;
    }

    // Set up the server address structure
    struct sockaddr_in sin;

    // Convert the IP address string to a binary representation
    inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr); // this will create a big endian 32 bit address

    // Set the address family of the sin structure to AF_INET, which indicates that the address is an IPv4 address.
    sin.sin_family = AF_INET;

    // Set the port number to 9999 and convert it to big-endian format
    sin.sin_port = htons(53);

    // Send the packet to the server
    int sent_bytes = sendto(s, (const char *)&packet_header, sizeof(packet_header) + packet_question_len, 0, (struct sockaddr *)&sin, sizeof(sin));

    // Print the number of bytes sent
    printf("---------------------------\n");
    printf("Sent %d bytes via UDP \n", sent_bytes);

    // Reuse same struct, reset data
    char response[4096];

    // Set struct size
    socklen_t addr_len = sizeof(sin);

    // Wait for response from the server
    int received_bytes = recvfrom(s, response, sizeof(response), 0, (struct sockaddr *)&sin, &addr_len);

    // Check response from the server
    if (received_bytes < 0)
    {
        printf("---------------------------\n");
        printf("Error receiving response from the server\n");
    }
    else
    {
        // Process response
        printf("---------------------------\n");
        printf("Received %d bytes via UDP\n", received_bytes);

        // Print response stats
        printf("---------------------------\n");
        printf("RETURNED PACKET:\n");
        for (size_t i = 0; i < received_bytes; ++i)
        {
            // Se il byte è un carattere ASCII stampabile, visualizzalo
            if (response[i] >= 32 && response[i] <= 126)
            {
                printf("%c", (unsigned char)response[i]);
            }
            else
            {
                // Stampa il byte in formato esadecimale
                printf("\\x%02X", (unsigned char)response[i]);
            }
        }
        printf("\n");

        // Set len of data answer section
        int len_answer = received_bytes - sent_bytes;

        // Set offset of data answer section
        int offset_len = sent_bytes;

        // Print address
        printf("---------------------------\n");
        printf("DATA ANSWER SECTION:\n");
        for (size_t i = 0; i < len_answer; i++)
        {
            // Print ASCII char
            if (response[offset_len + i] >= 32 && response[offset_len + i] <= 126)
            {
                printf("%c", (unsigned char)response[offset_len + i]);
            }
            else
            {
                // Print byte
                printf("\\x%02X", (unsigned char)response[offset_len + i]);
            }
        }
        printf("\n");

        // Init answer struct
        dns_answer answer;

        // Reset all data
        memset(&answer, 0, sizeof(answer));

        // Index to keep track of where to store the next character
        size_t index = 0;

        // Start from next byte after xCO (to set CNAME offset)
        int offset_cname = response[offset_len + 1];

        for (;;)
        {
            // Get current char
            char inputChar = response[offset_cname + index];

            // Break the loop if null terminator is encountered
            if (inputChar == '\0')
            {
                // Set index to start after cname offset (to proccess remaining data)
                index = 2;
                break;
            }

            // Store the character in answer.data
            answer.name[index] = inputChar;

            // Increment the index
            index++;

            // Break the loop if the array is full to avoid buffer overflow
            if (index >= sizeof(answer.name))
            {
                printf("Error array limit buffer reached\n");
                break;
            }
        }

        // Print NAME
        printf("---------------------------\n");
        printf("NAME: ");
        for (size_t i = 1; i < sizeof(answer.name); i++)
        {
            // Break the loop if null terminator is encountered
            if (answer.name[i] == '\0')
            {
                break;
            }

            if (i == answer.name[0] + 1)
            {
                printf(".");
                continue;
            }

            printf("%c", answer.name[i]);
        }

        printf("\n");

        // Copy data buffer to struct
        memcpy(&answer.type, &response[offset_len + index], sizeof(unsigned short));
        index += sizeof(unsigned short);
        memcpy(&answer.tClass, &response[offset_len + index], sizeof(unsigned short));
        index += sizeof(unsigned short);
        memcpy(&answer.ttl, &response[offset_len + index], sizeof(int));
        index += sizeof(int);
        memcpy(&answer.rdlength, &response[offset_len + index], sizeof(unsigned short));
        index += sizeof(unsigned short);
        memcpy(&answer.rdata, &response[offset_len + index], ntohs(answer.rdlength));

        // Print TYPE
        printf("---------------------------\n");
        printf("TYPE: %d\n", ntohs(answer.type));

        // Print CLASS
        printf("---------------------------\n");
        printf("CLASS: %d\n", ntohs(answer.tClass));

        // Print TTL
        printf("---------------------------\n");
        printf("TTL: %lu\n", ntohl(answer.ttl));

        // Print RDLENGTH
        printf("---------------------------\n");
        printf("RD_LENGTH: %d\n", ntohs(answer.rdlength));

        // Print address
        printf("---------------------------\n");
        printf("RD_DATA (IP ADDRESS): ");
        for (int i = 0; i < 4; i++)
        {
            // Print number
            if (i < 3)
            {
                printf("%d.", (unsigned char)answer.rdata[i]);
            }
            else // Remove last dot
            {
                printf("%d", (unsigned char)answer.rdata[i]);
            }
        }
        printf("\n");
    }

    // Close the socket
#ifdef _WIN32
    closesocket(s);
    WSACleanup(); // Cleanup Winsock on Windows
#else
    close(s);
#endif
    printf("---------------------------\n");
    printf("CONNECTION CLOSED ---------\n");

    return 0;
}