totp 2fa token generator.


Shows the current, and the next token. I was bored having to wait for the next timestep.

For copying to the xorg clipboard, xclip needs to be installed and within $PATH.
(https://github.com/astrand/xclip)


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
                 Default ist 5 minutes, -s 0 disables the timeout
 -q N[h|m]     : quit after N seconds (minutes, hours)
 -h            : Show this help

misc 2023, GPL
github.com/michael105/totp
</pre>



miSc 2023, Michael Myer, GPL

www.github.com/michael105/totp

