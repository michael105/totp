totp 2fa token generator.


Shows the current, and the next token. I was bored having to wait for the next timestep.

For copying to the xorg clipboard, xclip needs to be installed and within $PATH.
(https://github.com/astrand/xclip)

To display the tokens as popup within X, dzen can be used. 
(https://github.com/robm/dzen)


By default, the base32 secret is read from stdin,
to prevent someone sneaking at the process list to be able
to read secrets. (process arguments are shown)



compile with 'make'.


This needs currently 64bit instructions,
and is tested only with linux.


The system time needs either to be set to UTC,
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
 -n source     : use ntpc time, source one of a,c,f,g,m
                 (apple,cloudflare,facebook,google,microsoft)
                 microsoft will crash or point to apple - type jicrosoft or icrosoft instead
 -z            : display tokens with dzen2
 -X EXE ARG .. : display tokens with dzen2 / another program
                 EXE is started and piped to, with all following arguments
                 example: totp -X dzen2 -w 200 -fg white -bg black
 -x            : copy current token to the xserver clipboard (needs xclip)

 -h            : Show this help

misc147 2023, GPL
github.com/michael105/totp
</pre>



miSc147 2023, GPL

www.codeberg.org/misc1/totp



