totp 2fa token generator.


Shows the current, and the next token. I was bored having to wait for the next timestep.

For copying to the xorg clipboard, xclip needs to be installed and within $PATH.

By default, the base32 secret is read from stdin,
to prevent someone sneaking at the process list to be able
to read secrets. (process arguments are shown)



compile with 'make'.


This needs currently 64bit instructions,
and is tested only with linux.





miSc 2023, Michael Myer, GPL

