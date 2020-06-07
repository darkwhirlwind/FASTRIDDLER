# FASTRIDDLER
FASTRIDDLER is a suite in currently in development to automate buidling and running of exploits. FASTRIDDLER is designed as an educational project for the erudation of the coder with no paticular use case. Its currently limited to building stack based buffer overflows that require most mitigation techniques including W^X, ASLR, and stack canaries off.

FASTRIDDLER is designed to be interoperable with the metasploit framework to widden its range of possibilities.

FASTRIDDLER's current components include:

	*payload_packer : a tool designed to accept shellcode and output a payload for a buffer overflow.

FASTRIDDLER currently depends on python 3.8 to function due to changes in the binascii API.
