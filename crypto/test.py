import crypto_monero as cm
import ed25519_dholth as ed25519
import binascii
import random
import hashlib

def test_hash():
	M = 'hello world'
	h1 = cm.H(M.encode())

	s = hashlib.sha3_256()
	s.update(M.encode())
	h2 = s.hexdigest()[2:].encode()

	print(h1)
	print(h2)

def test_encode_decode():
	for i in range(0,10):
		x = random.randint(-ed25519.q,ed25519.q) % ed25519.l
		x_encoded = ed25519.encodeint(x)
		x_hexlified = binascii.hexlify(x_encoded)
		x_decoded = ed25519.decodeint(x_encoded)
		if x != x_decoded:
			print('---NOT MATCH--- x=',x)
			print(x_encoded)
			print(x_hexlified)
			print(x_decoded)

		if i % 7 == 0:
			print(x_encoded)
			print(x_hexlified)
			print(str(x).encode())
			print(x_decoded)

def test_add_mult_int():
	print(ed25519.l)
	x = -10
	y = 11
	a = -12
	sum_int = (x-a*y) % ed25519.l
	print(sum_int)


def test_Schnorr_Signatures():
	success = True
	for i in range(0,200):
		sk_hex, PK_hex = cm.gen_keypair()
		msg = str(random.randint(0,ed25519.q))
		Q_hex,sig_hex = cm.schnorr_signature(msg, sk_hex)
		if not cm.schnorr_verify(msg, PK_hex, Q_hex, sig_hex):
			print('---NOT MATCH---')
			print(Q_hex)
			print(sig_hex)
			success = False
		if i % 33 == 0:
			print(Q_hex)
			print(sig_hex)
	print('success' if success else 'fail')

def test_AOS_Signature():
	fail = []
	for i in range(5):
		sk_hex, PK_hex = cm.gen_keypair(0)

		for size in range(1,15):
			decoy_group = cm.create_decoy_group(size)
			M = str(random.randint(0,ed25519.q))

			for index_pi in range(0,size):
				e0, s_list, PK_list = cm.aos_ring_signature(M, decoy_group, PK_hex,sk_hex,index_pi)
				result = cm.aos_ring_verify(M, PK_list, e0, s_list)
				result_packet = (i,size,index_pi,'success' if result else 'FAIL')
				
				if not result:
					print('%d-th(pos. test), sz=%d, pi=%d, %s'%result_packet)
					fail.append(result_packet)

				if i % 25 == 0:
					print('%d-th(pos. test), sz=%d, pi=%d, %s'%result_packet)

		for size in range(1,15):
			sk_fake_hex, _ = cm.gen_keypair(0)
			decoy_group = cm.create_decoy_group(size)
			M = str(random.randint(0,ed25519.q))

			for index_pi in range(0,size):
				e0, s_list, PK_list = cm.aos_ring_signature(M, decoy_group, PK_hex,sk_fake_hex)
				result = cm.aos_ring_verify(M, PK_list, e0, s_list)
				result_packet = (i,size,index_pi,'success' if not result else 'FAIL')
				
				if result:
					print('%d-th(neg. test), sz=%d, pi=%d, %s'%result_packet)
					fail.append(result_packet)

				# if i % 25 == 0:
				print('%d-th(neg. test), sz=%d, pi=%d, %s'%result_packet)

		# if i % 3 == 0:
		# 		print('tested %d-th'%(i))

	print('-- result --')
	print('# of FAIL: ',len(fail))
	print(fail)

def test_Borromean_Signature_single():
	# for c in range(100):
	PK_matrix = []
	PK_vector = []
	sk_vector = []
	num_row = 5

	M = 'hello'

	for i in range(0,num_row):
		g = cm.create_decoy_group(4)
		PK_matrix.append(g)

	for i in range(0,num_row):
		sk, PK = cm.gen_keypair(0)
		sk_vector.append(sk)
		PK_vector.append(PK)

	e0,s,PK_matrix = cm.borromean_ring_signature(M, PK_matrix, PK_vector, sk_vector)
	print('---------')
	print('e0:',e0)
	print('s:',s)
	print('============verifiy')
	print(cm.borromean_verify(M, PK_matrix, e0, s))

def test_Borromean_Signature_batch():
	success = True
	num_err = 0
	for i in range(100):
		for num_row in range(1,6):
			for ring_size in range(1,6):

				PK_matrix = []
				PK_vector = []
				sk_vector = []

				M = str(random.randint(0,ed25519.q))

				# create group
				for j in range(0,num_row):
					g = cm.create_decoy_group(4)
					PK_matrix.append(g)

				# create secret key
				for k in range(0,num_row):
					sk, PK = cm.gen_keypair(0)
					sk_vector.append(sk)
					PK_vector.append(PK)

				e0,s,PK_matrix = cm.borromean_ring_signature(M, PK_matrix, PK_vector, sk_vector)
				result = cm.borromean_verify(M, PK_matrix, e0, s)
				if not result:
					num_err += 1
				
				print('%d: {#r: %d, #n: %d, result: %s}'%(i,num_row,ring_size,'success' if result else 'fail'))

		print('===== Done %d-th test'%(i))

	print('DONE with %s'%('no error' if success else '%d errors'%(num_err)))



def test_curve1():
	sk = b'd17f7ee37fc904cd04692a0db2a8aa003008de6865d7b0ed7c1515b9892cca03'
	PK = cm.scalarmult_base(sk)
	# sk, PK = gen_keypair()
	alpha_hex = cm.rand()
	print(sk)
	print(PK)
	print(alpha_hex)

	print('------ ------ ------')

	alpha_int_1 = ed25519.decodeint(binascii.unhexlify(alpha_hex))
	# alpha_int_2 = ed25519.decodeint(alpha_hex)
	# alpha_int_3 = int.from_hexs(alpha_hex,byteorder='big')
	# print('{',alpha_int_1)
	# print('{',alpha_int_2)
	# print('{',alpha_int_3)
	# print(':',binascii.hexlify(ed25519.encodeint(alpha_int_1)))

	sk_int_1 = ed25519.decodeint(binascii.unhexlify(sk))


	alphaPK_hex = cm.scalarmult(PK, alpha_hex)
	print('1: ',alphaPK_hex)

	PK_pt = ed25519.decodepoint(binascii.unhexlify(PK))
	alphaPK_pt = ed25519.decodepoint(binascii.unhexlify(alphaPK_hex))

	print(ed25519.isoncurve(PK_pt))
	print(ed25519.isoncurve(alphaPK_pt))

	print('------ ------ ------')

	# (alpha * sk) mod l
	sk_x_alpha_int = (alpha_int_1 * sk_int_1) % ed25519.l


	print(sk_x_alpha_int)
	sk_x_alpha_hex = binascii.hexlify(ed25519.encodeint(sk_x_alpha_int))
	print(sk_x_alpha_hex)
	print(ed25519.decodeint(binascii.unhexlify(sk_x_alpha_hex)))

	sk_x_alpha_x_G_hex = cm.scalarmult_base(sk_x_alpha_hex)
	print('2: ',sk_x_alpha_x_G_hex)

	sk_x_alpha_x_G_pt = ed25519.decodepoint(binascii.unhexlify(sk_x_alpha_x_G_hex))
	print(ed25519.isoncurve(sk_x_alpha_x_G_pt))

	print('------ ------ ------')
	print(alphaPK_pt==sk_x_alpha_x_G_pt)

if __name__ == '__main__':
	test_hash()
	# test_sig_1()
	# test_curve()
	# test_curve1()
	# test_encode_decode()
	# test_add_mult_int()
	# test_Schnorr_Signatures()
	# test_AOS_Signature()
	# test_Borromean_Signature_single()
	# test_Borromean_Signature_batch()