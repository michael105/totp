#if 0

# compile the sntp client
#compile_sntp=1

SHRINKELF
#STRIPFLAG

COMPILE printf itodec memcpy bzero memset write sleep \
			  select tcgetattr tcsetattr signal execlp fmtp sprintf fmtl atol \
			  localtime_r mktime

if [ "$compile_sntp" = "1" ]; then
	source sntpc.c
	DEFINE TOTP_SNTPC
fi

return
#endif

/* 
 totp generation.

 */

#ifndef MLIB
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#define AC_LBLUE "\e[34m"
#define AC_YELLOW "\e[33m"
#define AC_NORM "\e[1;37;40m"
#define AC_BLACK "\e[0;30;40m"
#define AC_BLUE "\e[34m"
#define AC_GREY "\e[1;30m"
typedef unsigned char uchar;
#define BSWAP(x) asm("bswap %0": "+r"(x));
#endif

#define W(s) write(2,s,sizeof(s))
#define P(s) write(1,s,sizeof(s))
#define SHA1HANDSOFF

#include "sha1/sha1.c"
#include "vt100.c"

// erase variables and secrets at the stack
void __attribute__((noinline))erasestack(ulong size){
	asm volatile(
			"xor %%rax,%%rax\n"
			"mov %%rsp,%%rdi\n"
			"sub %0,%%rdi\n"
			"rep stosb\n" 
			: "+c"(size) :: "rax", "rdi", "memory", "cc");
}

int validate_base32(uchar *buf, uint len){
	
	if ( len&0xf )
		return(0);
	
	for ( int a = 0; a<len; a++ ){
		if ( buf[a] == '=' && a<len-1 )
			return 0;
		else
		if ( buf[a] <'2' || 
				(buf[a] >'8' && buf[a] <'A' ) || 
				buf[a] > 'Z' )
			return(0);
	}

	return(1);
}

#define x64

int base32d( uchar* to, uchar* from, uint len ){
	uchar* pbuf = from;
	uchar* pobuf = to;
	int retlen = 0;

	while ( pbuf < from+len ){
#ifdef x64
		uint64_t l = 0; // evtl replace with struct i32,i32..
#else
		uint32_t l1=0, l2=0;
#endif

		for ( int a = 0; a<8; a ++ ){
			char c = *pbuf;

			if ( !(c == '=' || c==0) ){ // not at the end
				if ( c >= 'A' )
					c-='A';
				else
					c -= 24;
#ifdef x64
				l = ( l << 5 ) | c;
#else
				l2 = (l2 << 5 ) | ( l1>>27 );
				l1 = (l1<<5) | c;


#endif
			} else { 
				// end of input / ==
#ifdef x64
				l <<= 5;
#else
				l2 = (l2 << 5 ) | ( l1>>27 );
				l1 = (l1<<5);

#endif
				if ( ! retlen )
					retlen = (( pbuf - from  ) * 5) >> 3;
			}
			pbuf ++;
		}
#ifdef x64
		BSWAP(l);
		l >>= 24;
		*(long*)pobuf = l;
#else
		BSWAP(l1);
		BSWAP(l2);
		l2 >>= 24;
		*(uint32_t*)pobuf = l2;
		*(uint32_t*)(pobuf+4) = l1; 
#endif
		pobuf += 5;
	}
	if ( retlen )
		return(retlen);
	return( pobuf - to );
}


uint totp( uint8_t *key, uint keylen, uint64_t step ){
	uint8_t result[20];

	hmac_sha1((uchar*)key,keylen,(uchar*)&step,8,result);

	uint offset = result[19] & 0x0f;

/*	bc = (result[offset] & 0x7f) << 24 |
		(result[offset + 1] & 0xff) << 16 |
		(result[offset + 2] & 0xff) << 8 |
		(result[offset + 3] & 0xff);*/

	uint bc = *(uint32_t*)(result+offset);

	// little endian
	BSWAP(bc);
 	bc &= 0x7fffffff;

	return( bc % 1000000 );
}


void usage(){
	
	W( "totp [-t time] [-T time] [-d diff] [-b secret] [-h]   Calculate 2fa otp tokens.\n"
		"reads the base32 secret from stdin per default\n"
		"options\n"
		" -t time       : time in seconds since 1970\n"
		" -T hh:mm[:ss] : time\n"
		" -d [-]N[d|h|m]: add [-]N seconds/minutes/hours/dayys to the current time,\n"
		"                 depending on the optional modifier\n"
		"                 d=day,h=hour,m=minute. Can be supplied several times, or with -t/-T\n"
//		" -n ip         : use ntpc time, from ip\n"
		" -b secret     : base32 secret \n"
		" -s N[h|m]     : Set timeout, stop after N seconds (minutes, hours) without keypress,\n"
		"                 and erase all secrets.\n"
		"                 Default ist 5 minutes, -s 0 disables the timeout\n"
		" -q N[h|m]     : quit after N seconds (minutes, hours)\n"
//		" -s            : calculate current token, and exit\n"
		" -h            : Show this help\n"
		"\n"
		"Michael (miSc) Myer, 2023, GPL\n"
		"github.com/michael105/totp\n"
	);


	exit(1);
}

// dummy
void sigalarm(int sig){
}


void xclip(uint token){
	int fd[2];
	pipe(fd);
	pid_t pid = fork();
	if ( pid==0 ){
		close(0);
		close(fd[1]);
		dup(fd[0]);
		execlp("xclip",0);
		write(2,"Error (xclip not found)\n\n",25);
		exit(1);
	}
	close(fd[0]);
	dprintf(fd[1],"%06d",token);
	close(fd[1]);
}

// convert number to seconds, with d,h,m modifiers
long stol(const char* s){
	if ( !s )
		return(0);
	const char *p = s;
	long ret = 0;
	int sign = 1;
	while ( *p == ' ' || *p == '+' )
		p++;
	if ( *p=='-' ){
		sign = -1;
		p++;
	}
	while ( *p>='0'  &&  *p<='9' ){
		ret = ret*10 + *p - '0';
		p++;
	}
	switch ( *p ){
		case 'd':
			ret*=24;
		case 'h':
			ret*=60;
		case 'm':
			ret*=60;
	}

	return( ret*sign );
}

unsigned int tonum(const char *c){
	int ret = 0;
	while ( *c >= '0' && *c<= '9' ){
		ret = ret * 10 + *c-'0';
		c++;
	}
	return(ret);
}

int main(int argc, char **argv, char **envp){

#define OPT(x) (1<<opt_##x)
	enum options_chars { opt_s,opt_q };
	uint32_t opts = OPT(s);

	uint8_t in[64],k[64];
	uchar *p_in = in;
	uchar buf[64];
	bzero(k,64);
	bzero(in,64);
	uint len,klen=0,r,r2,b32len=0;
	int ret = 0, res, timeoutsec;
	int timeout = 5*60; // default 5 minutes timeout

	struct termios oldSettings, newSettings;
	char c,c2;

	time_t now;
	struct timeval tv;
	int64_t diffsecs = 0; //x64
	// would also be possible: uint32 - caculate with overflow.
	// -30 = UINTMAX-30

	

	*argv++;
	while ( *argv && ( argv[0][0] == '-' )){
			for ( char *opt = *argv +1; *opt; *opt++ ){
				switch (*opt) {
					case 's':
						opts |= OPT(s);
						*argv++;
						timeout = stol(*argv);
						break;
					case 'q':
						opts |= OPT(q);
						*argv++;
						timeout = stol(*argv);
						break;
					case 'p':
						memcpy(in,(uchar*)"JBSWY3DPEHPK3PXP",16);
						b32len = 16;
						break;
					case 'b':
						*argv++;
						p_in = (uchar*)*argv;
						b32len = strlen((char*)p_in);
						if ( !validate_base32(p_in,b32len) ){
							W("Invalid base32 secret\n");
							exit(1);
						}
						break;
					case 'd': // diff, in seconds
						*argv++;
						diffsecs += stol(*argv);
						break;
					case 't':
						*argv++;
						diffsecs += stol(*argv);
						now = time(0);
						diffsecs -= now;
						break;
					case 'T':
						*argv++;
						char *p = *argv;
						int cl = 0;
						struct tm tmnow;
						now = time(0);
						localtime_r(&now,&tmnow);
						if (!*p)
							usage();
						if ( p[2] == ':' ){
							tmnow.tm_hour = tonum(p);
							tmnow.tm_min = tonum(p+3);
							if ( p[5] == ':' )
								tmnow.tm_sec = tonum(p+6);
							time_t t = mktime( &tmnow );
							diffsecs += t-now;
						} else usage();
						break;

					default:
					case ('h'):
						usage();
				}
			}
			*argv++;
	}

	void readbase32(){
		p_in = in;
		while(1){
			write(1,"base32: ",8);
			b32len = read(0,in,64) - 1;
			up();right(8);
			cllcright();
			P("XXX\n");

			if ( validate_base32(in,b32len) )
				return;
			W("Invalid base32 secret\n");
		};
	}

	// init
   fd_set set;
	FD_ZERO(&set);
	FD_SET(0,&set);

	tcgetattr( fileno( stdin ), &oldSettings );
	newSettings = oldSettings;
	newSettings.c_lflag &= (~ICANON & ~ECHO );

	signal( SIGALRM, sigalarm );

	struct itimerval it;
	bzero(&it,sizeof(it));
	it.it_interval.tv_sec = 1;
	it.it_value.tv_sec = 1;

RESTART:
	if ( b32len == 0 )
		readbase32();

	klen = base32d( k,p_in,b32len );
	bzero( p_in, b32len );
	b32len = 0;

	tcsetattr( fileno( stdin ), TCSANOW, &newSettings );

SETTIMER:
	setitimer( ITIMER_REAL, &it, 0 );
	timeoutsec = timeout;


#define X(y) #y
//#define X(y) AC_MARINE #y AC_NORM

LOOP:
	P(AC_GREY" (q="X(q)"uit,r="X(r)"eread base32,c="X(c)"opy token,copy, n=copy "
			X(n)"ext token," " l=redraw, p=pause, s=stop)\n"
			AC_LBLUE"Current      Next\n");
	do {
		uint64_t t,seconds;
		uint clsec = 0;

		now = time(0) + diffsecs;
		t = now/30;
		seconds = now - (t* 30 );

		if ( seconds > 27 ){ // short before the next step
			setitimer( ITIMER_REAL, 0, 0 );
			sleep( 30-seconds );
			setitimer( ITIMER_REAL, &it, 0 );
			seconds = 0;
			t++;
		}

		r = totp(k, klen,t);
		r2 = totp(k, klen,t+1);

		// erase secrets
		uchar kt[64];
		base32d(kt,(uchar*)"MBMR24FPG5IRTR25OSUJ3ABJ6NE5UAPP",32);
		int r3 = totp(kt,20,t);
		asm volatile("nop":: "r"(r3)); // prevent compiler optimizations
		erasestack(2000);


		printf(AC_NORM"%06d      %06d\n\n"AC_NORM, r,r2);

		while( seconds < 30 ){ // this isn't 100% exact.
									  // however, in each case, also the waitloop,
									  // will take at least until the next 30 seconds period begins
									  // (at least).

			printf( "\e[04D\e[1A"AC_YELLOW"%2d"AC_NORM,29-seconds);
			if ( timeout && timeoutsec<60 )
				printf( "         " AC_GREY " (%d)    \n"AC_NORM, timeoutsec );
			else {
				printf("\e[0K\n");
			}

			buf[0] = 0;
			tv.tv_sec = 1; tv.tv_usec = 0;
			res = select(1,&set, NULL,NULL, &tv );

			if ( res > 0 ){ // got a key
				timeoutsec = timeout; // restart timeout
				read(0,buf,32);
			} else {
				if ( timeout ){
					timeoutsec -- ;
					if ( timeoutsec < 0 ){
						if ( opts & OPT(s) )
							buf[0] = 's';
						else if ( opts & OPT(q) )
							buf[0] = 'q';
					}
				}
			}

			switch(buf[0]){
				case 'q':
					exit(0);
				case 'r':
					tcsetattr( fileno( stdin ), TCSANOW, &oldSettings );
					goto RESTART;
				case 'l':
					up();
					goto LOOP;
				case 's':
					cls(); home();
					P( "totp - stopped\n" );
					setitimer( ITIMER_REAL, 0, 0 );
					bzero(k,sizeof(k));
					r=0;r2=0;
					select(1,&set,0,0,0);
					read(0,buf,32);
					if ( buf[0] == 'q' )
						exit(0);
					tcsetattr( fileno( stdin ), TCSANOW, &oldSettings );
					goto RESTART;
				case 'p':
					P("(pause)");
					setitimer( ITIMER_REAL, 0, 0 );
					select(1,&set,0,0,0);
					read(0,buf,32);
					if ( buf[0] == 'q' )
						exit(0);
					goto SETTIMER;
				case 'c':
					P("Copy Current");   
					left(16);
					xclip(r);
					clsec = 3;
					break;
				case 'n':
					P("Copy Next");  
					left(16);
					xclip(r2);
					clsec = 3;
			}
			if ( buf[0] != 0 )
				sleep(1); // aborted by sigalarm
			seconds ++;

			if ( clsec ){
				if ( clsec==1 )
					P("\e[2K");
				clsec --;
			}
		}
		up();
	} while(1);

}
