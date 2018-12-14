#!/usr/bin/env python3
#lock

import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import ecdsa
import sys
from os import walk
from os.path import isfile, join

parser = argparse.ArgumentParser()
parser.add_argument('-d','--directory',required = True)
parser.add_argument('-p','--publicKeyPath',required = True)
parser.add_argument('-r','--privateKeyPath',required = True)
parser.add_argument('-s','--subject',required = True)
args = parser.parse_args()


directory = args.directory
publicKeyPath = args.publicKeyPath
privateKeyPath = args.privateKeyPath
subject = args.subject

pub_in = open(publicKeyPath, "r")

pub_subject = ""

for line in pub_in:
    if line.strip() == "subject:":
        pub_subject = pub_in.readline().strip()
        break

pub_in.close()

if pub_subject != subject:
    print("Subjects do not match! Aborting...")
    sys.exit()

pub_in = open(publicKeyPath, "r")

public_key = ""

for line in pub_in:
    if line.strip() == "subject:":
        break
    else:
        public_key += line

pub_in.close()

#Get and encrypt AES key

aes_key = get_random_bytes(16) #256 bit

rsa_key = RSA.import_key(public_key)
cipher_rsa = PKCS1_OAEP.new(rsa_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

#We will write the encrypted AES key to keyfile

keyfile_out = open("keyfile", "w")
keyfile_out.write(str(enc_aes_key))
keyfile_out.close()

#Get private key

priv_in = open(privateKeyPath, "r")

private_key = ""

for line in priv_in:
    if line.strip() == "type:":
        break
    else:
        private_key += line

priv_in.close()

#Sign with the locker's private key
rsa_key = RSA.import_key(private_key)
h = SHA256.new(enc_aes_key)
signature = pss.new(rsa_key).sign(h)

keyfile_sig_out = open("keyfile.sig", "w")
keyfile_sig_out.write(str(signature))
keyfile_sig_out.close()


#lock all files and files in sub directories in the specified directory
for path, subdirs, files in walk(directory):
    for name in files:
        read_file = open(join(path, name), "rb")
        text = read_file.read()
        print(text)
        read_file.close()

        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, mac = cipher.encrypt_and_digest(text)
        print(cipher.decrypt(ciphertext))

        write_file = open(join(path, name), "wb")
        [write_file.write(x) for x in (mac, ciphertext)]
        write_file.close()

#
# #lock all files and files in sub directories in the specified directory
# for path, subdirs, files in walk(directory):
#     for name in files:
#         read_file = open(join(path, name), "rb")
#         mac, ciphertext = [read_file.read(x) for x in (16, -1)]
#         read_file.close()
#
#         cipher = AES.new(aes_key, AES.MODE_GCM)
#         plaintext = cipher.decrypt(ciphertext)
#
#         print(plaintext)
#         print()
