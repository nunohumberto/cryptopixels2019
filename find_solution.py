#!/usr/bin/env python3

# Author: Nuno Humberto
# https://github.com/nunohumberto

import hashlib
import requests
import base64
import sys
import time

# This script finds solutions for the fifth level of the CTF qualifiers for Pixels Camp 2019.

def crack_header(): # This method calculates a hash for a token header with a valid timestamp which first byte equals 0x00
			 # And returns the cookie header that originated such hash.


	actual_timestamp = int(time.time())
	ba = bytearray()
	ba.append(0xe8)
	ba.append(0x03)
	ba.append(0x00)
	ba.append(0x00)
	ba.append(0x01)
	ba.append(0x00) # <- We will play with these two
	ba.append(0x00) # <- least significant bytes from the timestamp.	
	ba.append((actual_timestamp & 0xFF0000) >> 16) 
	ba.append((actual_timestamp & 0xFF000000) >> 24)
	ba.append(0x00)
	ba.append(0x00)
	ba.append(0x00)
	ba.append(0x00)

	sys.stdout.write("Searching for a valid header hash... ")
	for i in range(256):
		for j in range(256):
			h = hashlib.sha256()
			ba[6] = i
			ba[5] = j
			h.update(ba)
			if h.digest()[0] == 0:
				print("\nDone. The generated hash has the following timestamp: %d" % (ba[8] << 24 | ba[7] << 16 | ba[6] << 8 | ba[5]))
				print("Hash: %s\n" % h.digest().hex())
				return ba

				

def check_cookie(cookie): # Checks if the server recognized this cookie as valid. (i.e. it doesn't give us a new cookie)
	headers = {'Cookie' : 'session=' + cookie}
	r = requests.get("https://c5-fab4c112b229-ctf.pixels.camp/", headers=headers)
	return not ('Set-Cookie' in r.headers and "session=" in r.headers['Set-Cookie'])


def get_cookie(): # Requests a new valid cookie from the server.
	return requests.get("https://c5-fab4c112b229-ctf.pixels.camp/").headers['Set-Cookie'].split(";")[4].split(" ")[2].split('session=')[1]

def patch_cookie(prefix, cookiearr): # Patches a cookie with the header we calculated before
	for i in range(13):
		cookiearr[i] = prefix[i]


def crack_cookie(): # Generates a premium cookie that will be recognized as valid by the server.
				   # A chance of success of approximately 50% will be achieved after 177 attempts.
				   # A chance of success of approximately 90% will be achieved after 589 attempts.
				   # Check 'https://nunohumberto.pt/carddrop' and input a chance of 0.390625% (1/256)

	attempts = 1
	valid_prefix = crack_header()
	print("Searching for a valid signature...")
	while True:
		sys.stdout.write("Checking attempt %d... " % attempts)
		attempts = attempts + 1
		encoded = get_cookie()
		decoded = bytearray(base64.b64decode(encoded))
		patch_cookie(valid_prefix, decoded)
		re_encoded = base64.b64encode(decoded).decode()
		if check_cookie(re_encoded):
			print("Valid!\n")
			print("Your cookie: %s" % re_encoded)
			break
		else:
			print("Nope.")
			time.sleep(0.5)


crack_cookie()



