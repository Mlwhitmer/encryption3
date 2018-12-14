#!/usr/bin/env python3
#lock

import argparse
import Crypto.PublicKey import RSA
import ecdsa

parser = argparse.ArgumentParser()
parser.add_argument('-d','--directory',required = True)
parser.add_argument('-p','--publicKeyPath',required = True)
parser.add_argument('-r','--privateKeyPath',required = True)
parser.add_argument('-s','--subject',required = True)
args = parser.parse_args()


