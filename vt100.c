//vt100 ctl sequences

#define _P(s) write(1,s,sizeof(s))
// clear screen
void cls(){
	_P("\e[2J"); 
}
// clear line
void cll(){
	_P("\e[2K"); 
}
// clear line, from cursor right
void cllcright(){
	_P("\e[0K"); 
}
// clear line, from cursor left
void cllcleft(){
	_P("\e[1K"); 
}
// save cursor position
void csave(){
	_P("\e7");
}
// restore cursor position
void crest(){
	_P("\e8");
}

void home(){
	_P("\e[H");
}

void cgoto(int col, int row){
	char buf[32];
	int l = sprintf(buf,"\e[%d;%dH",col,row);
	write(1,buf,l);
}

#define __CWRITE(s) write(1,"\e[" s, sizeof("\e[" s ) )

// macros. this spares the sprintf, but needs constants for num
#define CUP(num) __CWRITE( #num "A" ); 
#define CDOWN(num) __CWRITE( #num "B" ); 
#define CRIGHT(num) __CWRITE( #num "C" ); 
#define CLEFT(num) __CWRITE( #num "D" ); 
#define CHOME() __CWRITE( "H" ); 
#define CLS() __CWRITE( "2J" ); 



// if sprintf isn't defined.
char* uitos(char *buf, uint i){
	int a=1;
	while ( a*10 <= i )
		a*=10;
	do{
		int r = ( i/a );
		*buf = r+'0';
		buf++;

		if ( a==1 )
			break;

		i -= a*r;
		a/=10;
	} while ( 1 );

	*buf = 0;
	return(buf);
}

void right(uint cols){
	char buf[16];
	int l = sprintf(buf,"\e[%uC",cols);
	write(1,buf,l);
}

void left(uint cols){
	char buf[16];
	int l = sprintf(buf,"\e[%uD",cols);
	write(1,buf,l);
}

void up(){
	_P("\e[1A");
}

void down(){
	_P("\e[1B");
}


#undef _P
