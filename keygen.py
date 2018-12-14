#!/usr/bin/env/ python3
#keygen

from Crypto.PublicKey import RSA
import argparse
from ecdsa import SigningKey

parser = argparse.ArgumentParser()
parser.add_argument('-t','--opt',required = True)
parser.add_argument('-s','--subject',required = True)
parser.add_argument('-pub','--publicKeyFile',required = True)
parser.add_argument('-priv','--privateKeyFile',required = True)
args = parser.parse_args()

option = args.opt
subj = args.subject
publicFile = args.publicKeyFile
privateFile = args.privateKeyFile

pub_out = open(publicFile, "wb")
priv_out = open(privateFile, "wb")

if str(option) == 'rsa':
	key = 1
elif str(option) == 'ec':
	key = 2
else:
	print("Incorrect options\n")
	exit(1)



if key == 1:
	k = RSA.generate(2048)
	pub_out.write(k.publickey().exportKey('PEM'))
	pub_out = open(publicFile,"a+")
	pub_out.write('\n')
	pub_out.write("subject:")
	pub_out.write('\n')
	pub_out.write(subj)
	pub_out.write('\n')
	pub_out.write("type:")
	pub_out.write('\n')
	pub_out.write('rsa')
	pub_out.write('\n')
	pub_out.close()
	
	priv_out.write(k.exportKey('PEM'))
	priv_out = open(privateFile,"a+")
	priv_out.write('\n')
	priv_out.write("type:")
	priv_out.write('\n')
	priv_out.write('rsa')
	priv_out.write('\n')
	priv_out.close()
elif key == 2:
	k = SigningKey.generate()
	pub_out.write(k.get_verifying_key().to_pem())
	pub_out = open(publicFile,"a+")
	#pub_out.write('\n')
	pub_out.write("subject:")
	pub_out.write('\n')
	pub_out.write(subj)
	pub_out.write('\n')
	pub_out.write("type:")
	pub_out.write('\n')
	pub_out.write('ec')
	pub_out.write('\n')
	pub_out.close()
	
	priv_out.write(k.to_pem())
	priv_out = open(privateFile,"a+")
	#priv_out.write('\n')
	priv_out.write("type:")
	priv_out.write('\n')
	priv_out.write('ec')
	priv_out.write('\n')
	priv_out.close()
