#!/usr/bin/env python3
#unlock

import argparse
import json
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from ecdsa import VerifyingKey, BadSignatureError
import sys
import os
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


#get keyfile and keyfile.sig
keyfile_in = open("keyfile", "rb")
keyfile = keyfile_in.read()
keyfile_in.close()

keyfile_sig_in = open("keyfile.sig", "rb")
keyfile_sig = keyfile_sig_in.read()
keyfile_sig_in.close()


#get locking party's public key
pub_in = open(publicKeyPath, "r")

public_key = ""

for line in pub_in:
    if line.strip() == "subject:":
        break
    else:
        public_key += line

pub_in.close()

#Get private key

priv_in = open(privateKeyPath, "r")

private_key = ""

for line in priv_in:
    if line.strip() == "type:":
        break
    else:
        private_key += line

priv_in.close()

#Verify keyfile.sig
vk = VerifyingKey.from_pem(public_key)
try:
    vk.verify(keyfile_sig, keyfile)
except:
    print("BAD SIGNATURE! Aborting...")
    sys.exit()

#Fetch AES key
rsa_key = RSA.import_key(private_key)
cipher_rsa = PKCS1_OAEP.new(rsa_key)
aes_key = cipher_rsa.decrypt(keyfile)


#Delete keyfile and keyfile.sig
os.remove("keyfile")
os.remove("keyfile.sig")


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

        write_file = open(join(path, name), "w")
        write_file.write(plaintext.decode())
        write_file.close()


