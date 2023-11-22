/* 
 * simple ntp client (library), oriented at rfc4330 (sntp memorandum), rfc5905,
 * rfc9109 (port randomization)  . (rfc8915 - nts - would need ssl layer)
 


 Work in progress -
 currently in git/sntp / git/ntpc	


 */

#ifndef SNTP_H
#define SNTP_H


// ==================  HEADER =====================


 // let's assume, those ip's don't change - should be checked and updated from time to time,
 // and should be used as backup only. In general a physically close server should be preferred
#define SNTP_IP(name) ({ enum {apple=0,cloudflare,facebook,google,microsoft };\
		in_addr_t ips[] = {  0x7d0efd11, 0x1c89fa2, 0x7b1d8681, 0x23efd8, 0x9396514 };\
		ips[name]; })

#define SNTP_IP_GOOGLE
#define SNTP_IP_APPLE
#define SNTP_IP_MICROSOFT
#define SNTP_IP_CLOUDFLARE
#define SNTP_IP_FACEBOOK


// time, in 1/(1<<32) fractional seconds (circa 0.23 nanoseconds)
// (high 32 bits are the seconds)
typedef uint64_t sntp_time;

// same, in network byte order
typedef uint64_t sntp_net_time;


// sntp timeval, given in seconds since 1900 and fractions of 1 seconds, 
// in network byte order
typedef union {
	sntp_net_time ntime; // network order, bswap for little endian
	struct {
		uint32_t nseconds;
		uint32_t nfraction; // fraction of a second. (read: seconds + fraction/((1<<32))
	};
} sntp_net_timeval;


#ifdef LITTLE_ENDIAN
// sntp timeval, given in seconds since 1900 and fractions of 1 seconds, 
// in local byte order
typedef union {
	sntp_time time; // local order
	struct {
		uint32_t fraction; // fraction of a second. (read: seconds + fraction/((1<<32))
		uint32_t seconds;
	};
} sntp_timeval;

#else
typedef union {
	sntp_time time; // local order
	struct {
		uint32_t seconds;
		uint32_t fraction; // fraction of a second. (read: seconds + fraction/((1<<32))
	};
} sntp_timeval;

#error Endianess not implemented
// not fully implemented, and not tested
#endif

// convert sntp_timeval between local and network byte order
sntp_timeval sntp_tv_ntol( sntp_net_timeval );
sntp_net_timeval sntp_tv_lton( sntp_timeval );

// conversion of a sntp_timeval to timeval and reverse
struct timeval sntp_to_tv( sntp_timeval );
sntp_timeval sntp_from_tv( struct timeval tv );


// Sntp network udp packet. This is compatible with later ntp versions,
// in later versions additional information is appended to this data structure.
typedef struct {
	union {
		uint8_t li_vn_mode; 
		struct { 
			uchar mode :3 ;
			uchar version :3 ;                 
			uchar leapind :2 ;        
		};
	};

	uint8_t stratum;          
	uint8_t poll;           
	uint8_t precision;       

	uint32_t rootDelay;      //  Total round trip delay time.
	uint32_t rootDispersion; //  Max error aloud from primary clock source.
	uint32_t refId;          //  Reference clock identifier.

	struct {
		sntp_net_timeval ref;
		sntp_net_timeval orig; // when sent from client, copied from ref (set by the client)
		sntp_net_timeval rx; // when received from server
		sntp_net_timeval tx; // when sent from server
	} stv;

} sntp_packet;              


// saves a sntp request and the according answer, 
// including the received sntp packet
// and calculated times
typedef struct {
	sntp_packet packet;
	sntp_net_timeval sent; // serves also as check (packet.stv.orig should be the same value)
	struct timeval recv; // at which local time the packet was received
	sntp_timeval latency; // time needed by the server, between recieve and send
	sntp_timeval servertime; // time the server sent the message 

	sntp_timeval timediff; // the difference between local time and server time
		// To get the current time, an addition of timediff with the current time is needed,
		// a negative value is calculated with overflow ( -30seconds = UINTMAX - 30 seconds )
	sntp_timeval timediff_abs; // the absolut difference, without sign
	sntp_timeval spread;// time of the worst case deviation
					// This is the (stochastical) maximum, 
					// the timediff could deviate of the server's time
					// ( transmission time: 20ms forward, 5ms back -> deviation
					// of the calculated time would be 7.5 ms, maximal deviation is 12.5ms 
					//   25ms forward,0ms back -> 12.5ms deviation calculated, real deviation 25ms )
	char serverinfo[16]; // short description

	in_addr_t ip; // ntp server ip

	int status; // the status, updated by send and recieve. 
					// The values are defined with SNTP_STATUS(type), 
					// type one of ready,sent,kiss,errno,received,ok
					// ok means received and all values calculated
					// kiss and errno indicate an error, the according code is saved in kiss/errno
	uint kiss; // kiss server code
	uint errnum;
	uint refid; // server time source
} sntp_request;


// sntp object orientied interface
typedef struct {
	int listsize;
	int reqs_sent;
	int reqs_open;
	int reqs_ok;

	int socketfd;
	struct sockaddr_in servaddr; 
	int timeout;

	// function pointers
	// add server, send requests, wait for answers, handle answers, empty list
	// send wait handle
	
	sntp_timeval timediff_abs; //lowest timediff of all requests
	sntp_timeval timediff;
	sntp_request reqlist[];
} sntp_client;


int sntp_client_init( sntp_client *client, int listsize );

// malloc
sntp_client* sntp_client_new(int listsize);
// stack
#define SNTP_CLIENT(name,listsize) char _name[sizeof(sntp_client)+listsize*sizeof(sntp_request)];\
	sntp_client name = (sntp_client)_name;\
	sntp_client_init( &name, listsize )

// verbose status message
// used for: server info, kiss(error) code info, client errors, errno, refid description
typedef struct { 
	union { char code[4]; uint32_t code_int; }; 
	char *text; 
} sntp_msg;



extern const sntp_msg sntp_ref_source[];
extern const sntp_msg sntp_kiss_code[];



// constants

// conversion between UTC and NTP
#define SNTP_TIMESTAMP_DELTA 2208988800ull

// ntp port
#define PORTNO 123

#define SNTP_STATUS(s) ({ \
		enum { ok=0, empty, ready, sent, kiss, errnum, received, bad }; \
		s; })

#define SNTP_MODE(m) ({ \
		enum { reserved, sym_act, sym_pass, client, server, broadcast }; \
		m; \
		})


#define SNTP_LEAPIND(li) ({ \
		enum { ok, sec61, sec59, alarm }; \
		li; \
		})


#define SNTP_STATUSRATUM(st) ({ enum { error=-1, kiss, primary, secondary }; st; })


#define SNTP_KISS_ENUM \
	enum { STEP, RMOT, RATE, NKEY, MCST, INIT, RSTR, DROP, DENY, CRYP, \
		BCST, AUTO, AUTH, ACST, RESP, TIOT } __SNTP__kiss_code;

#define SNTP_KISS(code) ({ SNTP_KISS_ENUM; code; })


// ============= ENDHEADER





#endif

