#!/usr/bin/env python3
#unlock

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


#get keyfile and keyfile.sig
keyfile_in = open("keyfile", "r")
keyfile = keyfile_in.read()
keyfile_in.close()

keyfile_sig_in = open("keyfile.sig", "r")
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

cipher_rsa = PKCS1_OAEP.new(private_key)
key = cipher_rsa.decrypt(keyfile)
print(key)

# key = RSA.import_key(public_key)
# h = SHA256.new(bytearray(keyfile))
# verifier = pss.new(key)

# verifier.verify(h, keyfile_sig)

