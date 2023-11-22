#if 0

COMPILE bcopy bzero connect exit htons memset ntohl read socket \
		  write htonl network strcpy asctime inet_aton localtime_r prints printf itohex \
		  PRINTF fmtb inet_ntoa_r select fmtd sendto recvfrom inet_ntoa usleep errno

STRIPFLAG
OPTFLAG -Os
#SHRINKELF

return
#endif
/* 
 * simple ntp client, rfc4330 (sntp memorandum), rfc5905,
 * rfc9109 (port randomization). 
		
 // there is somewhere some trouble with the timediff calculation.
 // simple_timediff and simple_gettime differ about 1/2 second
 // It's irrelevant for totp. so.
 // I did warn. And, it works, for totp.
 // Currently I need this myself, I'm fed up of setting my clock
 // each time.
   
(rfc8915 - nts - would need ssl layer)


 */


//notes (rfc2030)
//mode: unicast
//vn -> 1 (v.1.)
// kiss packet-> sntpv4 (rfc4330)


//#define DEBUG



#ifndef MLIB
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <errno.h>
#define uint32_t unsigned int
#define uchar unsigned char

#define eprintf(...) fprintf(stderr,__VA_ARGS__)
#define USE_ERRNO
#define BSWAP(x) asm("bswap %0" : "+r"(x):: "cc" )

#endif

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) {}
#endif


#if __BYTEORDER__ == __LITTLE_ENDIAN__
#define LITTLE_ENDIAN
#endif

#include "sntp.h"

#ifdef LITTLE_ENDIAN
#define LEBSWAP(x) BSWAP(x)
#else
#define LEBSWAP(x) {}
#endif

// This is all but complete, but I'm unable to find a list.
// iana doesn't help, many seem to use their own id's.
const sntp_msg sntp_ref_source[] = {
	  { {"LOCL"}, "uncalibrated local clock"},
	  { {"CESM"}, "calibrated Cesium clock"},
	  { {"RBDM"}, "calibrated Rubidium clock"},
	  { {"PPS\0"}, "calibrated quartz clock or other pulse-per-seconds source"},
	  { {"IRIG"}, "Inter-Range Instrumentation Group"},
	  { {"ACTS"}, "NIST telephone modem service"},
	  { {"USNO"}, "USNO telephone modem service"},
	  { {"PTB\0"}, "PTB (Germany) telephone modem service"},
	  { {"TDF\0"}, "Allouis (France) Radio 164 kHz"},
	  { {"DCF\0"}, "Mainflingen (Germany) Radio 77.5 kHz"},
	  { {"MSF\0"}, "Rugby (UK) Radio 60 kHz"},
	  { {"WWV\0"}, "Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz"},
	  { {"WWVB"}, "Boulder (US) Radio 60 kHz"},
	  { {"WWVH"}, "Kauai Hawaii (US) Radio 2.5, 5, 10, 15 MHz"},
	  { {"CHU\0"}, "Ottawa (Canada) Radio 3330, 7335, 14670 kHz"},
	  { {"LORC"}, "LORAN-C radionavigation system"},
	  { {"OMEG"}, "OMEGA radionavigation system"},
	  { {"GPS\0"}, "Global Positioning Service"},
	  { {"GOOG"}, "Google, atomic clock, leapseconds smeared" },
	  { {"GOES"}, "Geosynchronous Orbit Environment Satellite"},
	  { {"GAL\0"}, "Galileo Positioning System"},
	  { {"PPS\0"}, "Generic pulse-per-seconds"},
	  { {"HBG\0"}, "LF Radio HBG Prangins, HB 75 kHz"},
	  { {"JJY\0"}, "LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz" },
	  { {"NIST"}, "NIST telephone modem"},
	  { {{0}},"unkown" } // mark end
  };

const char* sntp_info_source( uint refid ){
 	const sntp_msg *s = sntp_ref_source;
	LEBSWAP(refid);
	printf("refid = %x\n",refid);
	while ( s->code_int != refid && s->code_int )
		s++;
	//if ( s->code_int )
	return(s->text);
	//return(inet_ntoa((struct in_addr)refid));
}

#if 1

// - ret 0 = IP. <0 : errno oder kiss_code >0 refid / ip
const sntp_msg sntp_kiss_code[] = {
		//{ -1, {"SOCK"}, "Unable to create socket" }, // better errno
		{ {"TIOT"}, "Timeout" },
		{ {"RESP"}, "Bad response" },
		// copied from the rfc
		{ {"ACST"}, "The association belongs to a anycast server" },
		{ {"AUTH"}, "Server authentication failed" },
		{ {"AUTO"}, "Autokey sequence failed" },
		{ {"BCST"}, "The association belongs to a broadcast server" },
		{ {"CRYP"}, "Cryptographic authentication or identification failed" },
		{ {"DENY"}, "Access denied by remote server" },
		{ {"DROP"}, "Lost peer in symmetric mode" },
		{ {"RSTR"}, "Access denied due to local policy" },
		{ {"INIT"}, "The association has not yet synchronized for the first time" },
		{ {"MCST"}, "The association belongs to a manycast server" },
		{ {"NKEY"}, "No key found, or untrusted" },
		{ {"RATE"}, "Rate exceeded. Access temporarily denied" },
		{ {"RMOT"}, "Breached connection." },
		{ {"STEP"}, "Association not yet resynchronized" },
		{{{0}},0} 
	};


#endif



sntp_timeval sntp_tv_ntol( sntp_net_timeval ntv ){
#ifdef LITTLE_ENDIAN
	sntp_timeval ltv;
	ltv.time = ntv.ntime;
	BSWAP(ltv.time);
	return(ltv);
#else
	return((sntp_timeval)ntv.ntime);
#endif
}

sntp_net_timeval sntp_tv_lton( sntp_timeval ltv ){
	// call sntp_tv_ntol 
	return( (sntp_net_timeval) sntp_tv_ntol( (sntp_net_timeval) ltv.time ).time );
}

struct timeval sntp_to_tv( sntp_timeval ltv ){
#if ULONG_MAX != (1UL<<64)-1
#error need 64bit
#endif
  struct timeval tv;
  tv.tv_sec = ltv.seconds - SNTP_TIMESTAMP_DELTA;
  tv.tv_usec = (uint)((ulong)( (ulong)ltv.fraction * 1000000UL ) / (ulong)(UINT_MAX));
  return(tv);
}


struct timeval sntp_timediff_to_tv( sntp_timeval ltv ){
#if ULONG_MAX != (1UL<<64)-1
#error need 64bit
#endif
  struct timeval tv;
  tv.tv_sec = ltv.seconds;// - SNTP_TIMESTAMP_DELTA;
  tv.tv_usec = (uint)((ulong)( (ulong)ltv.fraction * 1000000UL ) / (ulong)(UINT_MAX));
  return(tv);
}



sntp_timeval sntp_from_tv( struct timeval tv ){
	sntp_timeval stv;
	stv.seconds = tv.tv_sec + SNTP_TIMESTAMP_DELTA;
	stv.fraction = (uint)((ulong)((ulong)UINT_MAX*(ulong)tv.tv_usec)/1000000UL);
	return(stv);
}



struct timeval current_time( struct timeval now, sntp_request *req ){

	return(now);
}


#ifdef USE_ERRNO
#define RETERR(msg,e) { int err = errno; write(2,msg,sizeof(msg)); return(err); }
#define IF_ERRNO(e,cmp) if ( errno cmp )
#else
//#define RETERR(msg,e) { write(2,msg,sizeof(msg)); return(e); }
#define RETERR(msg,e) { eprintf( msg " - errno: %d\n",-e); return(e); }
#define IF_ERRNO(e,cmp) if ( -e cmp )
#endif

int open_socket(){
	return(socket( AF_INET, SOCK_DGRAM, 0 ));
}

// Send a sntp request, and fill the request structure
// returns: 0 = Ok
// sockfd is an open socket, or 0 (open a new socket, and return the fd)
int sntp_req_send( in_addr_t ip, sntp_request *req, int *sockfd ){
	if ( !req || !ip )
		RETERR( "Invalid arguments", -EFAULT);
#ifdef USE_ERRNO
	errno = 0;
#endif

	// create socket
	if ( *sockfd <= 0 ){
		*sockfd = open_socket();
	  	if ( *sockfd < 0  )
	  	//if ( (sockfd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0  )
			RETERR( "Cannot create cocket", *sockfd );
	}


	bzero( req, sizeof( sntp_request ) );
	req->status = SNTP_STATUS(empty);
	int ret;
	//sntp_packet packet;
	//bzero( &packet, sizeof( sntp_packet ) );
	req->packet.version = 4;
	req->packet.mode = SNTP_MODE(client);

	//
	struct sockaddr_in serv_addr; // Server address data structure.
	bzero( ( char* ) &serv_addr, sizeof( serv_addr ) );
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons( PORTNO );


	serv_addr.sin_addr.s_addr = ip;
	req->ip = ip;
	DBG("sockfd: %d ip: %x\n",*sockfd,ip);

	// store send time
	struct timeval tv;
	if ((ret = gettimeofday(&tv,0))<0)
		RETERR("Cannot read system time",ret);

	// leave req time in network byte order.
	// spares later the conversion, and saves few microseconds
	req->packet.stv.tx = req->sent = sntp_tv_lton( sntp_from_tv( tv ) );
	//packet.stv.tx = sntp_tv_lton( req->sent ); // network byte order

	req->status = SNTP_STATUS(ready); // initialized
	// send 
	if ( (ret = sendto( *sockfd, &req->packet, sizeof(sntp_packet), 0, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) ))<0 )
		RETERR("Cannot send",ret);

	req->status = SNTP_STATUS(sent); // on the way
	return(0);
}

// subtract t2 from t1
sntp_timeval sntp_tv_diff( sntp_timeval t1, sntp_timeval t2 ){
	sntp_timeval ret;
	ret.seconds = t1.seconds - t2.seconds;
	ret.fraction = t1.fraction - t2.fraction;
	if ( ret.fraction > t1.fraction )
		ret.seconds --;
	return( ret );
}
/* Handle a ntp server reply, calculate and fill the values in the sntp_request.
 All needed values for the calculations are stored by sntp_req_wait in the sntp_request structure.
 Errors are stored in the according structure members, status, kiss, refid. 
 returns 0, for ok, or the status code (SNTP_STATUS)
 
 */
int sntp_req_handle( sntp_request *r ){
	if ( !r ) return(SNTP_STATUS(bad));

	if ( r->status != SNTP_STATUS(received) )
		return( r-> status );

	if ( r->packet.stv.rx.nseconds == 0 )
		return(SNTP_STATUS(bad));

	r->refid = r->packet.refId;
	LEBSWAP(r->refid);
	if ( r->packet.stratum == 0 ){ // kisscode
		r->kiss = r->refid;
		r->status = SNTP_STATUS(kiss);
		return(SNTP_STATUS(kiss));
	}


	r->servertime = sntp_tv_ntol( r->packet.stv.tx );

	sntp_timeval lrec = sntp_from_tv( r->recv );

	r->latency.time = r->servertime.time - sntp_tv_ntol(r->packet.stv.rx).time;

	// the time needed for the transmission /2 
	// ( it is the medium, so this would be the worst case deviation)
	r->spread.time = lrec.time - sntp_tv_ntol( r->sent ).time - r->latency.time;
		//sntp_tv_diff( sntp_tv_diff( sntp_tv_ntol( r->sent ), lrec ), r->latency );
	//r->spread.seconds /= 2;
	//r->spread.fraction /= 2;
	r->spread.time /= 2;

	r->timediff.time = r->servertime.time - lrec.time - r->spread.time;
	if ( r->timediff.time > lrec.time )
		r->timediff_abs.time = lrec.time - r->spread.time - r->servertime.time;
	else 
		r->timediff_abs.time = r->timediff.time;


	return(SNTP_STATUS(ok));
}

/*
 Wait for the answer to one or more sent sntpc requests
 reqs[]: the array of requests, filled by sntp_req_send
 reqnum: count of sent requests
 waitnum: wait, until waitnum ntpc replies are received, or 
 timeout: timeout in milliseconds (1000 equals 1 seconds)
          -1: wait forever
 returns: the number of requests, still in the array and unanswered;
   or -errno for errors
    (110 is timeout - rfc says "connection timed out" rotfl
	  111 - Connection refused
	  112 - Host down )
*/
int sntp_req_wait( sntp_request reqs[], int reqnum, int waitnum, int sockfd, int timeout ){ 
	DBG("req_wait 1\n");
	// create socket
	if ( sockfd <= 0 )
	  	if ( (sockfd=open_socket())< 0  )
	  	//if ( (sockfd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0  )
			RETERR( "Cannot create cocket", sockfd );


	fd_set fds;
	FD_ZERO(&fds);
	FD_SET( sockfd, &fds );

	struct timeval tv;
	struct timeval tv_timeout; // when to stop
	struct timeval *p_tv;
	int maxfd = 0;
	int ret;
	int open_reqs = 0;

	DBG("req_wait 2\n");
	if ( timeout >= 0 ){
		int t = timeout - tv.tv_sec * 1000;
		tv.tv_sec = timeout/1000;
		tv.tv_usec = t*1000;

#ifndef LINUX // with linux, select updates the timeout timeval
		if ((ret = gettimeofday(&tv_timeout,0))<0)
			RETERR("Cannot read system time",ret);
		DBG("req_wait 3\n");
		tv_timeout.tv_sec += timeout/1000;

		tv_timeout.tv_usec += t*1000;
		if ( tv_timeout.tv_usec > 1000000 ){
			tv_timeout.tv_usec -= 1000000;
			tv_timeout.tv_sec += 1;
		}
#endif 

		p_tv = &tv;
	} else {
		p_tv = 0; // block indefinite
	}

	for ( int a = 0; a< reqnum; a++ ){
		if ( reqs[a].status == SNTP_STATUS(sent) ){
			open_reqs++;
		}
	}
	DBG("open_reqs: %d\n",open_reqs);

	if ( !open_reqs )
		RETERR("No requests", -EBADF);


	// receive loop
	while ( waitnum && open_reqs ){
		// check for packets
		while ((ret = select( sockfd+1, &fds, 0, 0, p_tv )) < 0){
			IF_ERRNO( ret, != EINTR)
				RETERR("select", ret);
		}
		DBG("ret: %d\n",ret);
		if ( ret == 0 ){
			RETERR("timeout",-ETIMEDOUT);
		}


		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));
		addr.sin_addr.s_addr = 0xff00ee00;
		sntp_packet packet;
		bzero(&packet, sizeof(packet));
		socklen_t st = sizeof(addr);
		errno = 0;

		DBG("addr: %p len: %u   errno: %d   ret: %d\n",&addr,st,errno,ret);
		int retry = 0;
		errno = 0;
		while ( (ret=recvfrom( sockfd, &packet, sizeof(sntp_packet), 
						0, (struct sockaddr*)&addr, &st )) < 0 ){
			DBG("ret: %d errno %d\n",ret,errno);
			IF_ERRNO( ret, != EAGAIN || retry > 3){
				RETERR("recv",ret);	
			}
			retry ++;
			usleep(1000);
		}
		struct timeval now;
		if ((ret = gettimeofday(&now,0))<0)
			RETERR("Cannot read system time",ret);


#ifdef DEBUG
		printf("addr: %p len: %u   errno: %d   ret: %d\n",&addr,st,errno,ret);
		for ( int a = 3; a>=0; a-- ) 
			printf("%x",(ushort)(addr.sin_addr.s_addr>>(a*8)));
		printf("\n++\n");
#endif

		for ( int a = 0; a<reqnum; a++ ){
			if ( ( reqs[a].status == SNTP_STATUS(sent) ) && (reqs[a].ip == addr.sin_addr.s_addr ) ){
				DBG("--\n");
				if ( reqs[a].sent.ntime == packet.stv.orig.ntime ){
					// ip matches, values match, seems to be the right packet
					waitnum--;
					open_reqs--;
					reqs[a].status = SNTP_STATUS(received);
					reqs[a].recv = now;//sntp_from_tv(now);
					DBG("Matched packet\n");
					// handle that later
					memcpy( &reqs[a].packet, &packet, sizeof(packet) );
					break;
				}
			}
		}
	}

	return( open_reqs );
}


int _sntp_simple_get(sntp_request *req, in_addr_t ip, int timeout){
	int sockfd = 0;
	bzero(req,sizeof(sntp_request));

	int ret;
	if ( (ret= sntp_req_send( ip, req, &sockfd)) != SNTP_STATUS(ok) )
		return(ret);

	if ( (ret = sntp_req_wait( req, 1,1, sockfd, timeout )) != SNTP_STATUS(ok) )
		return(ret);

	close(sockfd);

	ret = sntp_req_handle( req );
	return(ret);
}
	

// returns a timediff to the local time
int sntp_simple_gettimediff( struct timeval *tv, in_addr_t ip, int timeout ){
	sntp_request req;
	int ret;
	if ((ret=_sntp_simple_get( &req, ip, timeout) ) != SNTP_STATUS(ok) )
		return ret;
	//struct timeval tv;
	*tv = sntp_timediff_to_tv( req.timediff_abs );																	
	if ( tv->tv_usec >= 500000 ){ // get closer to the 'real time', if only seconds are used
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
	if ( req.timediff_abs.time < req.timediff.time ){ // negative difference
		tv->tv_sec = -tv->tv_sec;																	 
		tv->tv_usec = -tv->tv_usec;																	 
	}
	return(SNTP_STATUS(ok));
}

int sntp_simple_gettime( struct timeval *tv, in_addr_t ip, int timeout ){
	sntp_request req;
	int ret;

	if ((ret=_sntp_simple_get( &req, ip, timeout) ) != SNTP_STATUS(ok) )
		return ret;
	ret = gettimeofday(tv,0);
	sntp_timeval stv;
	stv.time = sntp_from_tv( *tv ).time + req.timediff.time;
	*tv = sntp_to_tv( stv );

	return(SNTP_STATUS(ok));
}



	

#ifndef TOTP_SNTP
int main( int argc, char **argv ){

	printf("ok\n");
  char buf[32];
  struct tm tmnow;
  time_t tnow;
	struct timeval tv,tvdiff;
	struct timeval tv_akt; 

	gettimeofday(&tv,0);
	tnow = tv.tv_sec;
	 localtime_r(&tnow,&tmnow);

	prints( AC_BLUE "Local time: ", asctime_r( &tmnow, buf ), AC_N );


	int ret = sntp_simple_gettimediff( &tvdiff, SNTP_IP(google), 1000 );

	printf("timediff: %ld  %ld\n",tvdiff.tv_sec,tvdiff.tv_usec);

	gettimeofday(&tv,0);

	tv_akt.tv_sec = tv.tv_sec+tvdiff.tv_sec;
	tv_akt.tv_usec = tv.tv_usec+tvdiff.tv_usec;
	printf("now sec: %u  usec: %u\n", tv_akt.tv_sec,tv_akt.tv_usec);
	
	tnow = tv_akt.tv_sec;

  localtime_r(&tnow,&tmnow);

	prints( AC_CYAN "Time: (UTC) Google ", asctime_r( &tmnow, buf ), AC_N );
	sntp_simple_gettime( &tv_akt, SNTP_IP(google),1000 );

	printf("now sec: %u  usec: %u\n", tv_akt.tv_sec,tv_akt.tv_usec);
	tnow = tv_akt.tv_sec;
  localtime_r(&tnow,&tmnow);
	prints( AC_CYAN "Time: (UTC) Google ", asctime_r( &tmnow, buf ), AC_N );



	sntp_simple_gettime( &tv_akt, SNTP_IP(apple),1000 );

	printf("now sec: %u  usec: %u\n", tv_akt.tv_sec,tv_akt.tv_usec);
	tnow = tv_akt.tv_sec;
  localtime_r(&tnow,&tmnow);

	prints( AC_CYAN "Time: (UTC) Apple ", asctime_r( &tmnow, buf ), AC_N );
	

	sntp_timeval stv = sntp_from_tv( tv );

	printf("sec: %u  usec: %u\n", tv.tv_sec,tv.tv_usec);

	printf("sntp sec: %u  fraction: %u\n",stv.seconds, stv.fraction );

	struct timeval tv2;
	gettimeofday(&tv2,0);
	sntp_timeval stv2 = sntp_from_tv( tv2 );

	printf("sec: %u  usec: %u\n", tv2.tv_sec,tv2.tv_usec);

	printf("sntp sec: %u  fraction: %u\n",stv2.seconds, stv2.fraction );

	sntp_timeval diff;
	diff.time = stv2.time - stv.time;

	printf("sntp sec: %u  fraction: %u\n",diff.seconds, diff.fraction );
	diff.time = stv.time - stv2.time;
	printf("sntp sec: %u  fraction: %u\n",diff.seconds, diff.fraction );


	exit(0);

	

	exit(0);
}

#endif
