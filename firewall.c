/// \file firewall.c
/// \brief Reads IP packets from a named pipe, examines each packet,
/// and writes allowed packets to an output named pipe.
/// Author: Chris Dickens (RIT CS)
/// Author: Ben K Steele (RIT CS)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.

/// posix needed for signal handling
#define _POSIX_SOURCE

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>     /* interrupt signal stuff is from here */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     /* read library call comes from here */
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include "filter.h"
#include "pktUtility.h"

/// maximum packet length (ipv4)
#define MAX_PKT_LENGTH 2048

#define HEADER_LENGTH 20

/// Type used to control the mode of the firewall
typedef enum FilterMode_E
{
   MODE_BLOCK_ALL,
   MODE_ALLOW_ALL,
   MODE_FILTER
} FilterMode;


/// Pipes_S structure maintains the stream pointers.
typedef struct Pipes_S
{
   FILE * in_pipe;               ///< input pipe stream
   FILE * out_pipe;              ///< output pipe stream
} Pipes_T;

/// FWSpec_S structure holds firewall configuration, filter and I/O.
typedef struct FWSpec_S
{
   char * config_file;           ///< name of the firewall config file
   char * in_file;               ///< name of input pipe 
   char * out_file;              ///< name of output pipe 
   IpPktFilter filter;           ///< pointer to the filter configuration
   Pipes_T pipes;                ///< pipes is the stream data storage.
} FWSpec_T;

/// fw_spec is the specification data storage for the firewall.
static FWSpec_T * fw_spec;

/// close the streams. Call this once at the end of a simulation.
/// @param pipetab pointer to the I/O streams
void close_pipes( Pipes_T *pipetab ) {

   if(pipetab->in_pipe != NULL)
   {
      fclose(pipetab->in_pipe);
      pipetab->in_pipe = NULL;
   }

   if(pipetab->out_pipe != NULL)
   {
      fclose(pipetab->out_pipe);
      pipetab->out_pipe = NULL;
   }
}

/// MODE controls the mode of the firewall. main writes it and filter reads it.
static volatile FilterMode MODE = MODE_FILTER;

/// NOT_CANCELLED flag written by main and read by the thread.
static volatile int NOT_CANCELLED = 1;

/// thread object for the filter thread
static pthread_t tid_filter;

static bool checkSum = false;

static bool pcap = false;

static FILE * pcapFILE;

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        uint32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} * pcapGlobalHeader;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} * pcapPacketHeader;

#define pcapMAGICNUMBER 0xa1b2c3d4
#define pcapLENGTH 65535

/// thread specific data key for pthread cleanup after cancellation.
//static pthread_key_t tsd_key;

/// The tsd_destroy function cleans up thread specific data (TSD).
/// The spawning thread passes this function into pthread_key_create before
/// starting the thread.
/// The thread instance calls pthread_setspecific(key, (void *) value)
/// where value is the dynamic thread specific data.
/// When the thread exits, infrastructure calls the destroy function to
/// dispose of the TSD. 
/// @param tsd_data pointer to thread specific data allocations to free/close
void tsd_destroy( void * tsd_data) {

   FWSpec_T *fw_spec = (FWSpec_T *)tsd_data;
   printf( "fw: thread destructor is deleting filter data.\n"); fflush( stdout);
   if ( fw_spec->filter ) 
   {
      destroy_filter( fw_spec->filter);
      fw_spec->filter = NULL; 
   }
   printf( "fw: thread destructor is closing pipes.\n"); fflush( stdout);
   free(fw_spec->in_file);
   free(fw_spec->out_file);
   free(fw_spec->config_file);
   close_pipes( &fw_spec->pipes);
   free(fw_spec);
   if (pcap){
       fclose(pcapFILE);
   }
} 




/// signal handler passes signal information to the subordinate thread so
/// that the thread can gracefully terminate and clean up.
/// @param signum signal that was received by the main thread.
static void sig_handler( int signum)
{
    if(signum == SIGHUP) {
        NOT_CANCELLED = 0;
        printf("\nfw: received Hangup request. Cancelling...\n");
        fflush( stdout);
        pthread_cancel(tid_filter);  // cancel on signal to hangup
    }
}

/// init_sig_handlers initializes sigaction and installs signal handlers.
static void init_sig_handlers() {

    struct sigaction signal_action;            // define sig handler table 

    signal_action.sa_flags = 0;               // linux lacks SA_RESTART 
    sigemptyset( &signal_action.sa_mask );    // no masked interrupts 
    signal_action.sa_handler = sig_handler;   // insert handler function

    sigaction( SIGHUP, &signal_action, NULL ); // for HangUP from fwSim
    return; 
} // init_sig_handlers 


/// Open the input and output streams used for reading and writing packets.
/// @param spec_ptr structure contains input and output stream names.
/// @return true if successful
static bool open_pipes( FWSpec_T * spec_ptr)
{
   spec_ptr->pipes.in_pipe = fopen( spec_ptr->in_file, "rb");
   if(spec_ptr->pipes.in_pipe == NULL)
   {
      printf( "fw: ERROR: failed to open pipe %s.\n", spec_ptr->in_file);
      return false;
   }

   spec_ptr->pipes.out_pipe = fopen( spec_ptr->out_file, "wb");
   if(spec_ptr->pipes.out_pipe == NULL)
   {
      printf( "fw: ERROR: failed to open pipe %s.\n", spec_ptr->out_file);
      return false;
   }

   return true;
}

/// Read an entire IP packet from the input pipe
/// @param in_pipe the binary input file stream
/// @param buf Destination buffer for storing the packet
/// @param buflen The length of the supplied destination buffer
/// @return length of the packet or -1 for error
static int read_packet(FILE * in_pipe, unsigned char* buf){
    unsigned int numBytes = 0;

    int len_read = -1; // assume error
    len_read = fread(&numBytes, sizeof(unsigned int), 1, in_pipe);
    if (numBytes <= 0 || numBytes >= MAX_PKT_LENGTH || len_read <= 0) return -1;

    len_read = fread(buf, numBytes, 1, in_pipe);
    if (len_read <= 0) return -1;
    return numBytes;
}

bool isCheckSumGood(unsigned char * pkt){
    unsigned int computedCheckSum = 0xFFFF;
    unsigned int word;
    for (int i = 0; i < HEADER_LENGTH; i+=2){
        if (i != 10){
            word = ( ((unsigned int)pkt[i] << 8) + (unsigned int)pkt[i+1] );
            printf("Word #%.2d: %.4x +\n", i/2, word);
            if ( (computedCheckSum += word) > 0xFFFF ) computedCheckSum -= 0xFFFF;
        }
        else{
            printf("....OMITTING CHECKSUM....\n");
        }
    }
    printf("----------------\n     Sum: %.4x\n", computedCheckSum);
    unsigned int sentChecksum = (((unsigned int)pkt[10] << 8) + (unsigned int)pkt[11] );
    printf("Pack CheckSum: %x  Computed CheckSum: %x\n\n", sentChecksum, 0xFFFF ^ computedCheckSum);
    printf("Source IP in Hex: %x\n", ExtractSrcAddrFromIpHeader(pkt));
    return (sentChecksum == (0xFFFF ^ computedCheckSum));
}

bool writeGlobalHeader(){
    pcapGlobalHeader h;
    h->magic_number = pcapMAGICNUMBER;
    h->version_major = 2;
    h->version_minor = 4;
    h->thiszone = 0;
    h->sigfigs = 0;
    h->snaplen = pcapLENGTH;
    h->network = 1;
    fwrite(&h->magic_number, 32, 1, pcapFILE);
    fwrite(&h->version_major, 16, 1, pcapFILE);
    fwrite(&h->version_minor, 16, 1, pcapFILE);
    fwrite(&h->thiszone, 32, 1, pcapFILE);
    fwrite(&h->sigfigs, 32, 1, pcapFILE);
    fwrite(&h->snaplen, 32, 1, pcapFILE);
    fwrite(&h->network, 32, 1, pcapFILE);
    return true;
}

bool writePacketHeader(unsigned int time){
    pcapPacketHeader h;
    h->ts_sec = time;
    h->ts_usec = 0;
    h->incl_len = pcapLENGTH;
    h->orig_len = pcapLENGTH;
    fwrite(&h->ts_sec, 32, 1, pcapFILE);
    fwrite(&h->ts_usec, 32, 1, pcapFILE);
    fwrite(&h->incl_len, 32, 1, pcapFILE);
    fwrite(&h->orig_len, 32, 1, pcapFILE);
    return true;
}

/// Runs as a thread and handles each packet. It is responsible
/// for reading each packet in its entirety from the input pipe,
/// filtering it, and then writing it to the output pipe. The
/// single void* parameter matches what is expected by pthread.
/// return value and parameter must match those expected by pthread_create.
/// @param args pointer to an FWSpec_T structure
/// @return pointer to static exit status value which is 0 on success

static void * filter_thread(void* args){
    fflush(stdout);
    if (pcap){
        pcapFILE = fopen("blockedPackets.pcap", "wb");
        if (!writeGlobalHeader()) fprintf(stderr, "ERROR: failed to create global PCAP header");
    }
    unsigned char pktBuf[MAX_PKT_LENGTH];
    bool isCheckSumValid = true;
    unsigned int time = 0;
    //bool success;
    int length;
    static int status = EXIT_FAILURE; // static for return persistence
    status = EXIT_FAILURE; // reset
    FWSpec_T * fw = (FWSpec_T*) args;
    while(true){
        length = read_packet(fw->pipes.in_pipe, pktBuf);
        if (length > 0){
            time += 50;
            if (checkSum) isCheckSumValid = isCheckSumGood(pktBuf);
            if ( (MODE == MODE_FILTER  && isCheckSumValid && filter_packet(fw->filter, pktBuf)) || MODE == MODE_ALLOW_ALL){
                fwrite(&length, sizeof(int), 1, fw->pipes.out_pipe);
                fwrite(pktBuf, length, 1, fw->pipes.out_pipe);
                fflush(fw->pipes.out_pipe);
            }
            else if (pcap){
                if (!writePacketHeader(time)) fprintf(stderr, "ERROR: failed to write pcap packet header");
                fwrite(pktBuf, length, 1, pcapFILE);
            }
        }
    }   
    // end of thread is never reached when there is a cancellation.
    printf( "fw: thread is deleting filter data.\n"); fflush( stdout);
    tsd_destroy( (void *)fw);
    printf("fw: thread returning. status: %d\n", status);
    fflush( stdout);
    status = EXIT_SUCCESS;
    pthread_exit( &status);
}

FWSpec_T * createFWSpec(char * configFile, char * inFile, char * outFile){
    FWSpec_T * fw = malloc(sizeof(FWSpec_T));
    fw->config_file = malloc(strlen(configFile) + 1);
    strcpy(fw->config_file, configFile);
    fw->in_file = malloc(strlen(inFile) + 1);
    strcpy(fw->in_file, inFile);
    fw->out_file = malloc(strlen(outFile) + 1);
    strcpy(fw->out_file, outFile);
    fw->filter = create_filter();
    if (!configure_filter(fw->filter, fw->config_file)){
        return NULL;
    }
    if(!open_pipes(fw)) return NULL;
    return fw;
}


/// Displays a prompt to stdout and menu of commands that a user can choose
static void display_menu(void)
{
   printf("\n\n1. Block All\n");
   printf("2. Allow All\n");
   printf("3. Filter\n");
   printf("0. Exit\n");
   printf("> ");
   fflush(stdout);
}

/// The firewall main function creates a filter and launches filtering thread.
/// Then it handles user input with a simple menu and prompt.
/// When the user requests and exit, the main cancels and joins the thread
/// before exiting itself.
/// Run this program with the configuration file as a command line argument.
/// @param argc Number of command line arguments; 1 expected
/// @param argv Command line arguments; name of the configuration file
/// @return EXIT_SUCCESS or EXIT_FAILURE
int main(int argc, char* argv[])
{
    
    // print usage message if no arguments
    if(argc < 2)
    {
        fprintf(stderr, "usage: %s configFileName [-c Verify Checksum] [-l pcap Format]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 3){
        if (!strcmp(argv[2], "-c")) checkSum = true;
        if (!strcmp(argv[2], "-l")) pcap = true;
    }
    if (argc == 4){
        if (!strcmp(argv[2], "-c") || !strcmp(argv[3], "-c")) checkSum = true;
        if (!strcmp(argv[2], "-l") || !strcmp(argv[3], "-l")) pcap = true;
    }
    if ((argc == 4 && (!checkSum || !pcap)) || (argc == 3 && (!checkSum && !pcap))){
        fprintf(stderr, "usage: %s configFileName [-c Verify Checksum] [-l pcap Format]\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("fw: starting filter thread.\n");

    char * inPipe = "ToFirewall";
    char * outPipe = "FromFirewall";
    char * configFile = argv[1];
    display_menu();
    init_sig_handlers();
    fw_spec = createFWSpec(configFile, inPipe, outPipe);
    if (fw_spec == NULL) return EXIT_FAILURE;
    //pthread_setspecific(tsd_key, (void*) fw_spec); Dont need Probably?
    //pthread_create(&tid_filter, NULL, filter_thread, (void*)fw_spec);
    if (pthread_create(&tid_filter, NULL, filter_thread, (void*)fw_spec)){
        fprintf(stderr, "Failed to create Filter Thread.\n");
        return EXIT_FAILURE;
    }
    char c;
    while((c = getchar())){
        switch(c){
            case '1':
                printf("blocking all packets\n> ");
                MODE = MODE_BLOCK_ALL;
                continue;
            case '2':
                printf("allowing all packets\n> ");
                MODE = MODE_ALLOW_ALL;
                continue;
            case '3':
                printf("filtering packets\n> ");
                MODE = MODE_FILTER;
        }
        if (c == '0'){
            pthread_cancel(tid_filter);
            NOT_CANCELLED = 0;
            printf(">\nExiting firewall\n");
            break;
        }
    }

    printf( "fw: main is joining the thread.\n"); fflush( stdout);

    // wait for the filter thread to terminate
    void * retval = NULL;
    int joinResult = pthread_join(tid_filter, &retval);
    if( joinResult != 0)
    {
        printf( "fw: main Error: unexpected joinResult: %d\n", joinResult);
        fflush( stdout);
    }
    if ( (void*)retval == PTHREAD_CANCELED )
    {
        tsd_destroy(fw_spec);
        printf( "fw: main confirmed that the thread was canceled.\n");
    }
    printf( "fw: main returning.\n"); fflush( stdout);
    return EXIT_SUCCESS;
}
