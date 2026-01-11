

totp: vt100.c totp.c sha1/sha1.c sha1/sha1.h
	gcc -o totp totp.c

totp_sntp: vt100.c totp.c sha1/sha1.c sha1/sha1.h sntp/sntp.h sntp/sntp.c
	gcc -o totp totp.c -DTOTP_SNTP=1

bin:
	minimake totp.c
	cp totp ./amd64/
	cd amd64 && sha512sum totp > sha512sum.txt


