#ifdef mlconfig

# compile the sntp client
compile_sntp=1

SHRINKELF
#STRIPFLAG

COMPILE printf itodec memcpy bzero memset write sleep \
			  select tcgetattr tcsetattr signal _execlp snprintf atol \
			  localtime_r mktime execvp 
COMPILE fmtp fmtl fmtd open error MLVALIST strncpy

if [ "$compile_sntp" = "1" ]; then
	source sntp/sntp.c
	DEFINE TOTP_SNTP
fi

return
#endif

/* 
 totp generation.

 misc 2023-2025, GPL, github.com/michael105/totp

 */

#include "config.h"


#ifndef MLIB
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netinet/in.h>

#define AC_LBLUE "\e[1;34m"
#define AC_YELLOW "\e[1;33m"
#define AC_NORM "\e[1;37;40m"
#define AC_BLACK "\e[0;30;40m"
#define AC_BLUE "\e[0;34m"
#define AC_GREY "\e[1;30m"
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
#define BSWAP(x) asm("bswap %0": "+r"(x));
#endif

#define W(s) write(2,s,sizeof(s))
#define P(s) write(1,s,sizeof(s))
#define V(s) write(1,s,sizeof(s))
#define v(fmt,...) printf(fmt,__VA_ARGS__)

#define SHA1HANDSOFF
#include "sha1/sha1.c"

#include "vt100.c"
#ifdef TOTP_SNTP
#include "sntp/sntp.c"
#endif

// erase variables and secrets at the stack, "below" the current frame
static inline void __attribute__((always_inline))erasestack(ulong size){
	asm volatile(
			"xor %%rax,%%rax\n"
			"mov %%rsp,%%rdi\n"
			"sub %0,%%rdi\n"
			"rep stosb\n" 
			: "+c"(size) :: "rax", "rdi", "memory", "cc");
}

// erase variables, secrets and return address(es), starting with the current stackframe
// it is only possible to exit to the system afterwards
static inline void __attribute__((always_inline))exit_erase(ulong size, int exitcode){
	asm volatile(
			"xor %%rax,%%rax\n"
			"mov %%rsp,%%rdi\n"
			"rep stosb\n" 
			: "+r"(exitcode), "+c"(size) :: "rax", "rdi", "memory", "cc");
	exit(exitcode);
}

// validate base32 secret, convert lower to upper
int validate_base32(uchar *buf, uint len){
	
	if ( len&0xf )
		return(0);
	
	for ( int a = 0; a<len; a++ ){
		if ( buf[a] == '=' && a<len-1 )
			return 0;
		else
			if ( buf[a]>='a' && buf[a]<='z' ) buf[a] -= 32; 
			else
				if ( buf[a] <'2' || 
						(buf[a] >'8' && buf[a] <'A' ) || 
						buf[a] > 'Z' )
					return(0);
	}

	return(1);
}


// convert base32 to binary (secret)
int base32d( uchar* to, uchar* from, uint len ){
	uchar* pbuf = from;
	uchar* pobuf = to;
	int retlen = 0;

	while ( pbuf < from+len ){
		uint64_t l = 0; // evtl replace with struct i32,i32..

		for ( int a = 0; a<8; a ++ ){
			char c = *pbuf;

			if ( !(c == '=' || c==0) ){ // not at the end
				if ( c >= 'A' )
					c-='A';
				else
					c -= 24;
				l = ( l << 5 ) | c;
			} else { 
				// end of input / ==
				l <<= 5;
				if ( ! retlen )
					retlen = (( pbuf - from  ) * 5) >> 3;
			}
			pbuf ++;
		}
		BSWAP(l);
		l >>= 24;
		*(long*)pobuf = l;
		pobuf += 5;
	}

	if ( retlen )
		return(retlen);

	return( pobuf - to );
}

// otp genration
uint totp( uint8_t *key, uint keylen, uint64_t step ){
	uint8_t result[20];

	BSWAP(step);

	hmac_sha1((uchar*)key,keylen,(uchar*)&step,8,result);

	uint offset = result[19] & 0x0f;

	uint bc = *(uint32_t*)(result+offset);// & ~0x80;

	BSWAP(bc);
	bc = (bc<<1)>>1;

	return( bc % 1000000 );
}


void usage(){
	W( "totp [-t time] [-T time] [-d diff] [-b secret] [-p pipe] [-h]   Calculate 2fa otp tokens.\n"
		"\n"
		"options\n"
		" -I            : No interactive mode, read the secret from stdin\n"
		" -r            : read the secret from a pipe to stdin\n"
		" -p pipename   : read the secret from a named pipe, or a subshell\n"
		" -t time       : time in seconds since 1970\n"
		" -T hh:mm[:ss] : time\n"
		" -d [-]N[d|h|m]: add [-]N seconds/minutes/hours/days to the current time,\n"
		"                 depending on the optional modifier\n"
		"                 d=day,h=hour,m=minute. Can be supplied several times, or with -t/-T\n"
#ifdef TOTP_SNTP
		" -n source     : use ntpc time, source one of a,c,f,g,i\n"
		"                 (apple,cloudflare,facebook,google,icrosoft)\n"
		"                 (m)icrosoft will crash or point to apple - type jicrosoft or icrosoft instead\n"
#endif
		" -b secret     : base32 secret \n"
		" -s N[h|m]     : Set timeout, stop after N seconds (minutes, hours) without keypress,\n"
		"                 and erase all secrets.\n"
		"                 Default is 5 minutes, -s 0 disables the timeout\n"
		" -q N[h|m]     : quit after N seconds (minutes, hours)\n"
		" -z            : display tokens with dzen2 \n"
		" -X EXE ARG .. : display tokens with dzen2 / another program\n"
		"                 EXE is started and piped to, with all following arguments\n"
		"                 example: totp -X dzen2 -w 200 -fg white -bg black\n"
		" -x            : copy current token via xclip to the clipboard\n"
//		" -s            : calculate current token, and exit\n"
		" -h            : Show this help\n"
		" -v            : Display version\n"
		"\n"
		"version " VERSION "\n"
		"misc147, 2023-2025, GPL\n"
		"www.github.com/michael105/totp\n"
	);
	exit(1);
}

// dummy timeout handler
void sigalarm(int sig){
}


void xclip(uint token){
	int fd[2];
	pipe(fd);
	pid_t pid = fork();
	if ( pid==0 ){
		erasestack(2000); // shoot with cannons. erase secrets.
		close(0);
		close(fd[1]);
		dup(fd[0]);
		execlp(XCLIP_BIN,"xclip",NULL);
		write(2,"Error (xclip not found)\n\n",25);
		exit_erase(2000,1);
	}
	close(fd[0]);
	dprintf(fd[1],"%06d",token);
	close(fd[1]);
}


void dzen(int token, int nexttoken, int seconds, char **pexec){
	static int zenfd[2];
	if ( !zenfd[0] ){	
		pipe(zenfd);
		pid_t pid = fork();
		if ( pid==0 ){
			erasestack(2000); // shoot with cannons. why not. 
			close(0);
			close(zenfd[1]);
			dup(zenfd[0]);
// dzen2 exec
			if ( ! pexec ){
			execlp(DZEN_BIN,
					"dzen2","-w","200","-h","30",
					"-fn", "-*-*-*-*-*-*-18-","-fg","white", 
				NULL);

			write(2,"Error (dzen2 not found)\n\n",25);
			} else {
				execvp( *pexec, pexec );
				//eprintsl("Error, couldn't execute: ",*pexec);
				fprintf(stderr,"Error, couldn't execute: ");
				while (*pexec){
					write( STDERR_FILENO, *pexec, strlen( *pexec ) );
					*pexec++;
				}
				fprintf(stderr,"\n");
			}
			exit_erase(2000,1);
		}
		close(zenfd[0]);
	}
	dprintf(zenfd[1],"%06d (%d) %06d\n",token,seconds,nexttoken);
	//close(fd[1]);
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

#define OPTIONS s,q,I,r,p,n,z,x
#define SETOPT(opt) { enum { OPTIONS }; opts|= (1<<opt); }
#define DELOPT(opt) { enum { OPTIONS }; opts&= ~(1<<opt); }
#define OPT(opt) ({ enum { OPTIONS }; opts&(1<<opt); })
	uint32_t opts = 0;

	uint8_t in[64],k[64];
	uchar *p_in = in;
	uchar buf[64];
	bzero(k,64);
	bzero(in,64);
	uint klen=0,r,r2;
	int b32len=0;
	int res, timeoutsec;
	struct termios oldSettings, newSettings;
	int infd = 0; // read secret from
	int kfd = 0; // keyboard
	time_t now;
	struct timeval tv;
	int64_t diffsecs = 0; //x64
	in_addr_t sntp_ip = 0;
	// would also be possible: uint32 - caculate with overflow.
	// -30 = (UINTMAX-30) - UINTMAX
	char **pexec = 0;
	
	int timeout = 5*60; // default 5 minutes timeout
	SETOPT(s);

	// clear screen and quit 
 void quit(int ret){
		bzero(k, sizeof(k) );
		klen=0;
		if ( ret == 0 ){
			cls(); 
			// should also clean the scrolling history.
			// thinking about that, this would need it's own, virtual scrollback.
			// or no scrolling at all. Maybe later.
			home();
		}
		erasestack(4000);
		exit_erase(2000,ret);
	}
	// macro, optional exitcode
	# define QUIT(...) quit(__VA_OPT__(__VA_ARGS__) + 0 )

 void readbase32(){
		p_in = in;
		while(1){

			if ( !OPT(I) )
				write(1,"base32: ",8);
			b32len = read(infd,in,64) - 1;
			if ( b32len < 0 ){ // stdin closed, or another error
				W("Read error\n");
				exit(1);
			}

			if ( in[b32len] != '\n' )
				b32len++;

			if ( infd == 0 && !OPT(I) ){
				up();right(8);
				cllcright();
				P("XXX\n");
			}

			if ( validate_base32(in,b32len) )
				return;
			W("Invalid base32 secret\n");
		};
	}

 	void sighandle(int n){
		CLS();
		write(1,"\nquit\n",6);
		# define STSZ "8000"    // stacksize, to delete
		asm volatile(
			"mov %2,%0\n"
			"xor %%rax,%%rax\n"
			"mov $"STSZ",%%rcx\n"
			"add $1024,%%rcx\n" // delete above of main
			"mov %1,%%rdi\n"
			"sub $"STSZ",%%rdi\n"
			"rep stosb\n" 
			:"=b"(n) : "r"(&argc), "m"(n): "rax", "rdi", "memory", "cc");
		// getting segfaults, when assigning "+r"(n), "b"(n), .. (?)
		exit(n);
	}
	
	while ( *++argv && ( **argv == '-' ) ){
		for ( char *opt = *argv +1; *opt; *opt++ ){
			switch (*opt) {
				case 'I': 
					SETOPT(I);
					break;
				case 'r':
					SETOPT(r);
					break;
				case 'X':
					//*argv++;
					pexec = argv+1;
					while ( *++argv ){};
				case 'z':
					SETOPT(z);
					break;
				case 'x':
					SETOPT(x);
					break;

# ifdef TOTP_SNTP
//#error dsf
				case 'n':
					SETOPT(n);
					*argv++;
					int c = argv[0][0];
					c = (c-97)>>1;
					sntp_ip = SNTP_IP(c);
					//mv("c: %d ip: %x\n",c,sntp_ip);
					break;
# endif


				case 'p':
					SETOPT(p);
					*argv++;
					infd = open( *argv, O_RDONLY );
					if ( infd<=0 )
						error(1,errno,"Couldn't open %s\n",*argv);
					break;
				case 's':
					SETOPT(s);
					*argv++;
					timeout = stol(*argv);
					break;
				case 'q':
					SETOPT(q);
					DELOPT(s);
					*argv++;
					timeout = stol(*argv);
					break;
				case 'c':
					memcpy(in,(uchar*)"JBSWY3DPEHPK3PXP",16);
					b32len = 16;
					break;
				case 'b':
					*argv++;
					//p_in = (uchar*)*argv;
					strncpy( (char*)in, *argv, 64 );
					b32len = strlen((char*)p_in);
					if ( !validate_base32(p_in,b32len) ){
						W("Invalid base32 secret\n");
						QUIT(1);
					}
					memset(*argv-3,0,b32len+3); // erase argv
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
			/*	case 'n':
					*argv++;
					now = time(0);
					break;*/
				case 'T':
					*argv++;
					char *p = *argv;
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
				case 'v':
					printf("totp, misc147 (github.com/michael105/totp), version " VERSION "\n" );
					exit(0);

				default:
				case ('h'):
					usage();
			}
		}
	}


	// init
# ifdef TOTP_SNTP
	if ( sntp_ip ){
		v("Get sntp timediff, ip: %x\n",sntp_ip);
		struct timeval tvdiff,tv,tv_akt;
		int ret = sntp_simple_gettimediff( &tvdiff, sntp_ip, 1000 );
		if ( ret ){
			W("Error\n");
			exit(ret);
		}
		diffsecs = tvdiff.tv_sec;

		gettimeofday(&tv,0);

		tv_akt.tv_sec = tv.tv_sec+tvdiff.tv_sec;
		tv_akt.tv_usec = tv.tv_usec+tvdiff.tv_usec;
		printf("now sec: %lu  usec: %lu\n", tv_akt.tv_sec,tv_akt.tv_usec);

		time_t tnow = tv_akt.tv_sec;

		char buf[32];
		struct tm tmnow;
		localtime_r(&tnow,&tmnow);

		v( AC_CYAN "Time: (UTC) %s%s\n", asctime_r( &tmnow, buf ), AC_N );
	}
# endif




   fd_set set;
	FD_ZERO(&set);
	FD_SET(0,&set);

	if ( OPT(r) && !(OPT(p)) ){
		readbase32();
		close(0);
		kfd = open("/dev/tty", O_RDONLY|O_NOCTTY);
		if ( kfd <0 ){
			W("Error opening /dev/tty\n");
			exit(1);
		}
	}

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
	*(ulong*)k^=(ulong)&klen; // scramble key with stack address
	bzero( p_in, b32len );
	b32len = 0;
	
	if ( !OPT(I) )
		tcsetattr( fileno( stdin ), TCSANOW, &newSettings );

SETTIMER:
	setitimer( ITIMER_REAL, &it, 0 );
	timeoutsec = timeout;


#define X(y) #y
//#define X(y) AC_LGREY #y AC_GREY
	char tbuf[32];

LOOP:

	now = time(0) + diffsecs;
	struct tm tmnow;
	
	strftime( tbuf, 32, "UTC: %Y/%m/%d %H:%M:%S\n", localtime_r( &now, &tmnow ) );

	P( tbuf );

	if ( OPT(I) )
		P( AC_GREY "Ctrl+C to quit\n" );
	else
		P( AC_GREY" (q="X(q)"uit,r="X(r)"eread base32,c="X(c)"opy token,n=copy "
			X(n)"ext token," " l=redraw, p="X(p)"ause, s="X(s)"top)\n");
	P( AC_LBLUE"Current      Next\n");

	while (1) {
		uint64_t t,seconds;
		uint clsec = 0;

		now = time(0) + diffsecs;
		*(ulong*)k^=(ulong)&klen;
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
		//*(ulong*)k^=(ulong)&klen;
		asm("xorq %1,%0" : "+r"(*(ulong*)k) : "r"(&klen) );
		int r3 = totp(kt,20,t);
		asm volatile("nop":: "r"(r3)); // prevent compiler optimizations
		erasestack(2000);

		if ( OPT(x) )
			xclip(r);

		printf(AC_NORM"%06d      %06d\n\n", r,r2);

		while( seconds < 30 ){ // this isn't 100% exact.
									  // however, in each case, also the waitloop,
									  // will take at least until the next 30 seconds period begins
									  // (at least).

			if ( OPT(z) )
				dzen(r,r2,29-(int)seconds,pexec);

			printf( "\e[04D\e[1A"AC_YELLOW"%2d"AC_NORM,29-(int)seconds);
			if ( timeout && timeoutsec<60 )
				printf( "         " AC_GREY " (%d)    \n"AC_NORM, timeoutsec );
			else {
				printf("\e[0K\n");
			}

			buf[0] = 0;
			res=0;
			tv.tv_sec = 1; tv.tv_usec = 0;

			if ( OPT(I) )
				sleep(1);
			else
				res = select(1,&set, NULL,NULL, &tv );

			if ( res > 0 ){ // got a key
				timeoutsec = timeout; // restart timeout
				read(0,buf,32);
			} else {
				if ( timeout ){
					timeoutsec -- ;
					if ( timeoutsec < 0 ){
						if ( OPT(s) )
							buf[0] = 's';
						else if ( OPT(q) )
							buf[0] = 'q';
					}
				}
			}

			switch(buf[0]){
				case 'q':
					QUIT();
				case 'l':
					up();
					goto LOOP;
				case 's':
					cls(); home();
					P( "totp - stopped (q=quit)\n" );
					setitimer( ITIMER_REAL, 0, 0 );
					bzero(k,sizeof(k));
					r=0;r2=0;
					select(1,&set,0,0,0);
					read(0,buf,32);
					if ( buf[0] == 'q' )
						QUIT();
					//tcsetattr( fileno( stdin ), TCSANOW, &oldSettings );
					//goto RESTART;
				case 'r':
					tcsetattr( fileno( stdin ), TCSANOW, &oldSettings );
					cls();home();
					goto RESTART;

				case 'p':
					P("(pause)");
					setitimer( ITIMER_REAL, 0, 0 );
					select(1,&set,0,0,0);
					read(0,buf,32);
					if ( buf[0] == 'q' )
						QUIT();
					goto SETTIMER;
				case 'c':
				case ' ':
					P("Copy Current");   
					left(16);
					xclip(r);
					clsec = 3;
					break;
				case 'n':
				case '\n':
					P("Copy Next   ");  
					left(16);
					xclip(r2);
					clsec = 3;
			}
			if ( buf[0] != 0 )
				sleep(1); // aborted by sigalarm
			seconds ++;

			if ( clsec && !--clsec )
					P("\e[2K"); // clear line
		}
		up();
	};

}
