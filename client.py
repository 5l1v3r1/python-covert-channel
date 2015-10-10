import time
import argparse
import logging
from random import uniform, randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def char_packet(dest, char1, char2=None):
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    if(char2 is None):
        destport = ord(char1) << 8
    else:
        destport = (ord(char1) << 8) + ord(char2)
    destport = (destport ^ timeVar)
    return IP(dst=dest) / TCP(sport=get_srcport(), dport=destport, flags="S")


def port_packet(dest, destport, srcport=80):
    global args
    return IP(dst=dest) / TCP(sport=get_srcport(), dport=destport, flags="S")


def get_srcport():
    global args
    if(args.srcport is None):
        return 80
    elif(args.srcport == "random"):
        return randint(1500, 65535)
    else:
        return int(args.srcport)


def knock(dest):
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    sr1(port_packet(dest, 2525 + timeVar))
    delay_sleep()
    sr1(port_packet(dest, 14156 + timeVar))
    delay_sleep()
    sr1(port_packet(dest, 6364 + timeVar))


def disconnect(dest):
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    sr1(port_packet(dest, 13098 + timeVar))
    delay_sleep()
    sr1(port_packet(dest, 11514 + timeVar))


def end_msg(dest):
    timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
    randPort = randint(1500, 65535)
    packet = IP(dst=dest, id=timeVar) / TCP(dport=randPort, sport=get_srcport())
    sr1(packet)


def delay_sleep():
    global args
    if(args.delay is None):
        return
    randRange = args.delay.split('-')
    size = len(randRange)
    if(size == 1):
        time.sleep(int(randRange[0]))
    elif(size == 2):
        sleeptime = uniform(int(randRange[0]), int(randRange[1]))
        print("Waiting for {}s".format(sleeptime))
        time.sleep(sleeptime)

    else:
        sys.exit("Invalid input for delay")


def main(args):
    dest = args.destIP
    knock(dest)
    while True:
        msg = raw_input('Send: ')
        for char1, char2 in zip(msg[0::2], msg[1::2]):
            delay_sleep()
            sr1(char_packet(dest, char1, char2))
        if(len(msg) % 2):
            delay_sleep()
            sr1(char_packet(dest, msg[len(msg) - 1]))
        end_msg(dest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Python covert channel")
    parser.add_argument('destIP', help="Destination address")
    parser.add_argument('-s', '--srcport', help="Source port, defaults to 80")
    parser.add_argument('-d', '--delay', help="Delay between each send in seconds. Range allowed with a dash")
    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        print("Disconnecting...")
        disconnect(args.destIP)
