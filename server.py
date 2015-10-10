import sys
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def decode(packet):
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    if(packet[1].id == timeVar):
        sys.stdout.write('\n')
        return
    dport = packet[2].dport
    dport = (dport ^ timeVar)
    char1 = chr((dport >> 8) & 0xff)
    char2 = chr(dport & 0xff)
    if(char2 is not None):
        sys.stdout.write("{}{}".format(char1, char2))
    else:
        sys.stdout.write("{}".format(char1))
    sys.stdout.flush()


def parse(packet):
    global connecting_ips
    connIP = packet[1].src
    destport = packet[2].dport
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    knock1 = 2525 + timeVar
    knock2 = 14156 + timeVar
    knock3 = 6364 + timeVar
    dc1 = 13098 + timeVar
    dc2 = 11514 + timeVar

    if(connIP in connecting_ips):
        if(connecting_ips[connIP] == 3):
            if(destport == dc1):
                connecting_ips[connIP] = 4
                return
            decode(packet)
        elif(destport not in [knock2, knock3, dc2]):
            del connecting_ips[connIP]
        elif(destport == knock2 and connecting_ips[connIP] == 1):
            connecting_ips[connIP] = 2
        elif(destport == knock3 and connecting_ips[connIP] == 2):
            print("Receiving message from {}".format(connIP))
            connecting_ips[connIP] = 3
        elif(destport == dc2 and connecting_ips[connIP] == 4):
            del connecting_ips[connIP]
            print("{} has disconnected".format(connIP))
        else:
            del connecting_ips[connIP]
    elif(destport == knock1):
        connecting_ips[connIP] = 1


def main():
    print("Sniffing for traffic...")
    sniff(filter="tcp", prn=parse)


if __name__ == '__main__':
    connecting_ips = {}
    main()
