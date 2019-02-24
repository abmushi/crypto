from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
import base64
import codecs

def generate_onion_address(verbose=False):
	key = RSA.generate(1024)

	# Text encoding, done according to RFC1421/RFC1423.
	public_key_0 = key.publickey().exportKey("PEM")
	if verbose:
		print('PEM:',public_key_0)

	# Binary encoding.
	public_key_1 = key.publickey().exportKey("DER")
	if verbose:
		print('DER:',public_key_1)

	# Textual encoding, done according to OpenSSH specification. Only suitable for public keys (not private keys).
	public_key_2 = key.publickey().exportKey("OpenSSH")
	if verbose:
		print('OpenSSH:',public_key_2)

	h = SHA1.new()
	h.update(public_key_1[22:])
	sha_1_digest = h.hexdigest()
	half = sha_1_digest[0:20]

	b = codecs.decode(half,'hex')
	e = base64.b32encode(b)
	s1 = e.decode("utf-8")

	return s1[0:16].lower()+'.onion'

def from_private_key(pem_file):

	f = open(pem_file, "r")
	key = RSA.importKey(f.read())
	f.close()

	public_key_1 = key.publickey().exportKey("DER")

	h = SHA1.new()
	h.update(public_key_1[22:])
	sha_1_digest = h.hexdigest()
	half = sha_1_digest[0:20]

	b = codecs.decode(half,'hex')
	e = base64.b32encode(b)
	s1 = e.decode("utf-8")

	return s1[0:16].lower()+'.onion'

def generate_onion_address_v3(verbose=False):
	
	pass

def main():
	address0 = generate_onion_address()
	print('address:',address0)

	# https://www.peterbeard.co/blog/post/generating-a-vanity-onion-address/
	address1 = from_private_key('./a.pem')

	# should get 'examplelatozpqzz.onion'
	print('address(a.pem):',address1)

if __name__ == '__main__':
	main()

