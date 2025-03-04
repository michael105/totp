totp 2fa token generator, including a sntp network time server syncronization client.


Displays the current and the next token. I was bored having to wait for the next timestep,
and I'm using this myself for several years now.

For copying to the xorg clipboard, xclip needs to be installed and within $PATH.
(https://github.com/astrand/xclip)

To display the tokens as popup within xorg/.., dzen can be used. 
(https://github.com/robm/dzen)


By default, the base32 secret is read from stdin,
to prevent someone sneaking at the process list to be able
to read secrets. (process arguments might also be stored in the shell history)



compile with 'make'.


Currently 64bit instructions are needed,
tested at linux only.


If the sntp time server client isn't used,
either the system time needs to be set to UTC,
or the according time difference has to be supplied. (e.g. totp -d +2h)





<pre>
# totp -h

totp [-t time] [-T time] [-d diff] [-b secret] [-p pipe] [-h]   Calculate 2fa otp tokens.

options
 -I            : No interactive mode, read the secret from stdin
 -p pipename   : read the secret from a named pipe, or a subshell
 -t time       : time in seconds since 1970
 -T hh:mm[:ss] : time
 -d [-]N[d|h|m]: add (or subtract) [-]N seconds/minutes/hours/days to the current time,
                 depending on the optional modifier
                 d=day,h=hour,m=minute. Can be supplied several times, or with -t/-T
 -b secret     : base32 secret 
 -s N[h|m]     : Set timeout, stop after N seconds (minutes, hours) without keypress,
                 and erase all secrets.
                 Default is 5 minutes, -s 0 disables the timeout
 -q N[h|m]     : quit after N seconds (minutes, hours)
 -n source     : use ntpc time, source one of a,c,f,g,i
                 (apple,cloudflare,facebook,google,m(i)crosoft)
                 microsoft might crash or point to apple(!) - type (j)icrosoft or icrosoft instead
 -z            : display tokens with dzen2
 -X EXE ARG .. : display tokens with dzen2 / another program
                 EXE is started and piped to, with all following arguments
                 example: totp -X dzen2 -w 200 -fg white -bg black
 -x            : copy current token to the xserver clipboard (needs xclip)
 -v            : Display version info
 -h            : Show this help

</pre>



NOTES

If xclip, dzen or another program are used, you need to make sure, 
they are within PATH and it isn't possible to put there another script/binary.

It is more secure to use the option -X and provide an sbolute path,
or to change the hardcoded binary names into absolute paths.

The binary names are defined in config.h



misc147 2023-2025, GPL - miscNNN@disroot.org, replace NNN with the result of three times half of hundred, subtract 3.

github.com/michael105/totp 



