#!/usr/bin/env python3
#lock

import json
from base64 import b64encode, b64decode
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey
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
keyfile = b64encode(enc_aes_key).decode('utf-8')
keyfile_out.write(keyfile)
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

# #Sign with the locker's private key

sk = SigningKey.from_pem(private_key)
signature = sk.sign(keyfile.encode())

keyfile_sig_out = open("keyfile.sig", "wb")
keyfile_sig_out.write(signature)
keyfile_sig_out.close()

#lock all files and files in sub directories in the specified directory
for path, subdirs, files in walk(directory):
    for name in files:
        read_file = open(join(path, name), "rb")
        text = read_file.read()
        read_file.close()

        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, mac = cipher.encrypt_and_digest(text)

        json_k = ['nonce', 'ciphertext', 'mac']
        json_v = [b64encode(cipher.nonce).decode('utf-8'), b64encode(ciphertext).decode('utf-8'), b64encode(mac).decode('utf-8')]
        cipher_json = json.dumps(dict(zip(json_k, json_v)))

        write_file = open(join(path, name), 'w')
        write_file.write(str(cipher_json))
        write_file.close()

print()
#lock all files and files in sub directories in the specified directory
for path, subdirs, files in walk(directory):
    for name in files:
        read_file = open(join(path, name), "r")
        cipher_content = read_file.read()
        cipher_json = json.loads(cipher_content)
        cipher_json["nonce"] = b64decode(cipher_json["nonce"])
        cipher_json["ciphertext"] = b64decode(cipher_json["ciphertext"])
        cipher_json["mac"] = b64decode(cipher_json["mac"])

        cipher = AES.new(aes_key, AES.MODE_GCM, cipher_json["nonce"])
        plaintext = cipher.decrypt_and_verify(cipher_json["ciphertext"], cipher_json["mac"])
        #
        print(plaintext.decode())
        # print()
