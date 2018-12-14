.PHONY: All 

All:
	sudo pip install pycryptodome	
	sudo pip install ecdsa
	chmod +x keygen
	chmod +x lock
	chmod +x unlock
