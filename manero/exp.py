import ed25519_dholth as ed25519
from Crypto.Hash import keccak
import binascii
import random

# https://github.com/keis/base58
# import my_base58 as base58

# secret key
# arbitrary 256 bits = 32 bytes
spend_sk = b'd17f7ee37fc904cd04692a0db2a8aa003008de6865d7b0ed7c1515b9892cca03'
view_sk =  b'33c71dd92b22bfb25e8adfa25e2a7efb4565cbda457a2e0bc1aba021484d5f05'

def scalarmult_base(k_hex):
	a = ed25519.decodeint(binascii.unhexlify(k_hex))
	A = ed25519.scalarmult(ed25519.B,a)
	return binascii.hexlify(ed25519.encodepoint(A))

def scalarmult(P_hex,k_hex):
	a = ed25519.decodeint(binascii.unhexlify(k_hex))
	P = ed25519.decodepoint(binascii.unhexlify(P_hex))
	A = ed25519.scalarmult(P,a)
	return binascii.hexlify(ed25519.encodepoint(A))

def pt_add_hex(pt0_hex,pt1_hex):
	pt0 = ed25519.pt_xform( ed25519.decodepoint(binascii.unhexlify(pt0_hex)) )
	pt1 = ed25519.pt_xform( ed25519.decodepoint(binascii.unhexlify(pt1_hex)) )

	sum_pt = ed25519.pt_unxform( ed25519.xpt_add(pt0,pt1) )
	sum_hex = binascii.hexlify(ed25519.encodepoint(sum_pt))

	return sum_hex

def multiply_int(a_hex,b_hex):
	a_int = ed25519.decodeint(binascii.unhexlify(a_hex))
	b_int = ed25519.decodeint(binascii.unhexlify(b_hex))

	mult_int = (a_int*b_int) % ed25519.l
	mult_hex = binascii.hexlify(ed25519.encodeint(mult_int))

	return mult_hex

def H(v):
	h_obj = keccak.new(digest_bits=256)
	h_obj.update(v)

	# encode: string to byte
	# decode: byte to string
	# https://www.mkyong.com/python/python-3-convert-string-to-bytes/
	return h_obj.hexdigest().encode()

def rand(n=0):
	k_int = ed25519.genkey(n)
	return hex(k_int)[2:].encode()

def gen_keypair(n=0):
	sk = rand(n)
	PK = scalarmult_base(sk)
	return sk, PK

# Schnorr Signatures
# https://cryptoservices.github.io/cryptography/2017/07/21/Sigs.html
def schnorr_signature(M,sk_hex):
	alpha_hex = rand()
	Q_hex = scalarmult_base(alpha_hex)
	e_hex = H(M.encode()+Q_hex)

	alpha_int = ed25519.decodeint(binascii.unhexlify(alpha_hex))
	e_int = ed25519.decodeint(binascii.unhexlify(e_hex))
	sk_int = ed25519.decodeint(binascii.unhexlify(sk_hex))

	s_int = (alpha_int - e_int*sk_int) % ed25519.l
	s_hex = binascii.hexlify(ed25519.encodeint(s_int))
	return e_hex,s_hex

def schnorr_verify(M,PK_hex,e_hex,s_hex):
	sG_hex = scalarmult_base(s_hex)
	eP_hex = scalarmult(PK_hex, e_hex)

	sG = ed25519.pt_xform( ed25519.decodepoint(binascii.unhexlify(sG_hex)) )
	eP = ed25519.pt_xform( ed25519.decodepoint(binascii.unhexlify(eP_hex)) )

	Q_pt = ed25519.pt_unxform( ed25519.xpt_add(sG,eP) )
	Q_hex = binascii.hexlify(ed25519.encodepoint(Q_pt))
	ee_hex = H(M.encode()+Q_hex)

	return e_hex == ee_hex

# AOS Ring Signatures
def create_decoy_group(size=5):
	group = []
	for i in range(size):
		_, PK = gen_keypair(0)
		group.append(PK)
	return group

def aos_ring_signature(M,decoy_group,PK_hex,sk_hex,index_pi=-1):
	M_encoded = M.encode()
	index_pi = random.randint(0,len(decoy_group)) if index_pi == -1 else index_pi
	PK_pi = PK_hex
	decoy_group.insert(index_pi,PK_pi)
	e = [0]*len(decoy_group)
	s = [0]*len(decoy_group)
	u_hex = rand(0)
	uG_hex = scalarmult_base(u_hex)

	index_start = (index_pi+1) % len(decoy_group)

	e[index_start] = H(M_encoded+uG_hex)
	s[index_start] = rand(0)

	for cnt in range(1,len(decoy_group)):
		i = (index_start+cnt) % len(decoy_group)
		prev_i = (i-1) % len(decoy_group)
		s[i] = rand(0) if i != index_pi else 0
		temp = pt_add_hex(scalarmult_base(s[prev_i]),scalarmult(decoy_group[prev_i], e[prev_i]))
		e[i] = H(M_encoded+temp)

	u_int = ed25519.decodeint(binascii.unhexlify(u_hex))
	e_int = ed25519.decodeint(binascii.unhexlify(e[index_pi]))
	sk_int = ed25519.decodeint(binascii.unhexlify(sk_hex))

	s[index_pi] = binascii.hexlify(ed25519.encodeint((u_int-e_int*sk_int) % ed25519.l))

	return e[0],s,decoy_group

def aos_ring_verify(M,PK_list,e0,s_list):
	M_encoded = M.encode()
	e = [0]*len(s_list)
	e[0] = e0
	for i in range(1,len(PK_list)):
		temp = pt_add_hex(scalarmult_base(s_list[i-1]),scalarmult(PK_list[i-1], e[i-1]))
		e[i] = H(M_encoded+temp)

	temp = pt_add_hex(scalarmult_base(s_list[-1]),scalarmult(PK_list[-1], e[-1]))
	e[0] = H(M_encoded+temp)

	return e0==e[0]

# Borromean Ring Signatures
def borromean_ring_signature(M, PK_matrix, PK_vector, sk_vector,index_pi=-1):
	M_encoded = M.encode()
	index_pi = [0]*len(PK_matrix)
	u_hex = [0]*len(PK_matrix)
	uG_hex = [0]*len(PK_matrix)
	R = [0]*len(PK_matrix)
	e = [None]*len(PK_matrix)
	s = [None]*len(PK_matrix)

	# temp_s = [None]*len(PK_matrix)

	for row in range(0,len(PK_matrix)):

		# set index_pi
		index_pi[row] = random.randint(0,len(PK_matrix[row])) if index_pi==-1 else index_pi[row]

		# insert pk
		PK_matrix[row].insert(index_pi[row],PK_vector[row])

		e_row = [0]*(len(PK_matrix[row]))
		s_row = [0]*(len(PK_matrix[row]))
		# temp_s_row = ['None']*(len(PK_matrix[row]))

		# for connecting point
		u_hex[row] = rand(0)
		uG_hex[row] = scalarmult_base(u_hex[row])

		index_start = (index_pi[row] + 1) % len(PK_matrix[row])

		### case B1: [0,...,0,pi,st]
		if index_start == len(PK_matrix[row])-1:
			e_row[index_start] = H(M_encoded+uG_hex[row])
			s_row[index_start] = rand(0)
			R[row] = pt_add_hex(scalarmult_base(s_row[index_start]),scalarmult(PK_matrix[row][index_start], e_row[index_start]))

		### case B2: [0,...,pi,st,...,0]
		elif index_start > 0:
			e_row[index_start] = H(M_encoded+uG_hex[row])
			s_row[index_start] = rand(0)

			for i in range(index_start+1,len(PK_matrix[row])):
				temp = pt_add_hex(scalarmult_base(s_row[i-1]),scalarmult(PK_matrix[row][i-1], e_row[i-1]))
				e_row[i] = H(M_encoded+temp)
				s_row[i] = rand(0)

				if i == len(PK_matrix[row])-1:
					R[row] = pt_add_hex(scalarmult_base(s_row[i]),scalarmult(PK_matrix[row][i], e_row[i]))

		### case B3: [st,0,0,...,0,pi]
		else:
			R[row] = uG_hex[row]

		e[row] = e_row
		s[row] = s_row

	R_sum = b''
	for i in range(0,len(R)):
		R_sum += R[i]

	# set common e0
	e0 = H(M_encoded+R_sum)


	for row in range(0,len(PK_matrix)):
		e[row][0] = e0
		s[row][0] = rand(0)

		### case C1: [pi,st,0,...]
		if index_pi[row] == 0:
			u_int = ed25519.decodeint(binascii.unhexlify(u_hex[row]))
			e_int = ed25519.decodeint(binascii.unhexlify(e0))
			sk_int = ed25519.decodeint(binascii.unhexlify(sk_vector[row]))

			s[row][0] = binascii.hexlify(ed25519.encodeint((u_int-e_int*sk_int) % ed25519.l))

		### case C2: [0,pi,st,0,...] or [st,0,0,...,0,pi]
		else:
			# i up to pi (inclusive)
			for i in range(1,index_pi[row]+1):
				prev_i = i-1
				s[row][i] = rand(0)
				temp = pt_add_hex(scalarmult_base(s[row][prev_i]),scalarmult(PK_matrix[row][prev_i], e[row][prev_i]))
				e[row][i] = H(M_encoded+temp)

			u_int = ed25519.decodeint(binascii.unhexlify(u_hex[row]))
			e_int = ed25519.decodeint(binascii.unhexlify(e[row][index_pi[row]]))
			sk_int = ed25519.decodeint(binascii.unhexlify(sk_vector[row]))

			s[row][index_pi[row]] = binascii.hexlify(ed25519.encodeint((u_int-e_int*sk_int) % ed25519.l))

	return e0,s,PK_matrix

def borromean_verify(M,PK_matrix,e0,s_matrix):
	M_encoded = M.encode()
	R = [0]*len(PK_matrix)

	for row in range(len(PK_matrix)):
		e = [0]*len(s_matrix[row])
		e[0] = e0
		for i in range(1,len(PK_matrix[row])):
			temp = pt_add_hex(scalarmult_base(s_matrix[row][i-1]),scalarmult(PK_matrix[row][i-1], e[i-1]))
			e[i] = H(M_encoded+temp)
			if i == len(PK_matrix[row])-1:
				R[row] = pt_add_hex(scalarmult_base(s_matrix[row][i]),scalarmult(PK_matrix[row][i], e[i]))

	R_sum = b''
	for each in R:
		R_sum += each
	return e0 == H(M_encoded+R_sum)

def public_address(spend_pk,view_pk):
	temp0 = b'12'+spend_pk+view_pk

	temp1 = H(temp0)
	temp2 = temp0 + temp1.decode()[:8].encode()

	print(temp2)

	temp3 = base58.encode(temp2.decode())
	arr = [temp3[i:i+11] for i in range(0,len(temp3),11)]

	print(arr)

	# temp3_1 = temp2.decode()[:128]
	# temp3_2 = temp2.decode()[128:]
	# temp_array_1 = [temp3_1[i:i+16].encode() for i in range(0,len(temp3_1),16)]
	# temp_array_1.append(temp3_2)

	# print(temp_array_1)

	# temp_array_2 = [base58.b58encode(each) for each in temp_array_1]

	# print(temp_array_2)

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
		sk_hex, PK_hex = gen_keypair()
		msg = str(random.randint(0,ed25519.q))
		Q_hex,sig_hex = schnorr_signature(msg, sk_hex)
		if not schnorr_verify(msg, PK_hex, Q_hex, sig_hex):
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
		sk_hex, PK_hex = gen_keypair(0)

		for size in range(1,15):
			decoy_group = create_decoy_group(size)
			M = str(random.randint(0,ed25519.q))

			for index_pi in range(0,size):
				e0, s_list, PK_list = aos_ring_signature(M, decoy_group, PK_hex,sk_hex,index_pi)
				result = aos_ring_verify(M, PK_list, e0, s_list)
				result_packet = (i,size,index_pi,'success' if result else 'FAIL')
				
				if not result:
					print('%d-th(pos. test), sz=%d, pi=%d, %s'%result_packet)
					fail.append(result_packet)

				if i % 25 == 0:
					print('%d-th(pos. test), sz=%d, pi=%d, %s'%result_packet)

		for size in range(1,15):
			sk_fake_hex, _ = gen_keypair(0)
			decoy_group = create_decoy_group(size)
			M = str(random.randint(0,ed25519.q))

			for index_pi in range(0,size):
				e0, s_list, PK_list = aos_ring_signature(M, decoy_group, PK_hex,sk_fake_hex)
				result = aos_ring_verify(M, PK_list, e0, s_list)
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
		g = create_decoy_group(4)
		PK_matrix.append(g)

	for i in range(0,num_row):
		sk, PK = gen_keypair(0)
		sk_vector.append(sk)
		PK_vector.append(PK)

	e0,s,PK_matrix = borromean_ring_signature(M, PK_matrix, PK_vector, sk_vector)
	print('---------')
	print('e0:',e0)
	print('s:',s)
	print('============verifiy')
	print(borromean_verify(M, PK_matrix, e0, s))

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
					g = create_decoy_group(4)
					PK_matrix.append(g)

				# create secret key
				for k in range(0,num_row):
					sk, PK = gen_keypair(0)
					sk_vector.append(sk)
					PK_vector.append(PK)

				e0,s,PK_matrix = borromean_ring_signature(M, PK_matrix, PK_vector, sk_vector)
				result = borromean_verify(M, PK_matrix, e0, s)
				if not result:
					num_err += 1
				
				print('%d: {#r: %d, #n: %d, result: %s}'%(i,num_row,ring_size,'success' if result else 'fail'))

		print('===== Done %d-th test'%(i))

	print('DONE with %s'%('no error' if success else '%d errors'%(num_err)))



def test_curve1():
	sk = b'd17f7ee37fc904cd04692a0db2a8aa003008de6865d7b0ed7c1515b9892cca03'
	PK = scalarmult_base(sk)
	# sk, PK = gen_keypair()
	alpha_hex = rand()
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


	alphaPK_hex = scalarmult(PK, alpha_hex)
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

	sk_x_alpha_x_G_hex = scalarmult_base(sk_x_alpha_hex)
	print('2: ',sk_x_alpha_x_G_hex)

	sk_x_alpha_x_G_pt = ed25519.decodepoint(binascii.unhexlify(sk_x_alpha_x_G_hex))
	print(ed25519.isoncurve(sk_x_alpha_x_G_pt))

	print('------ ------ ------')
	print(alphaPK_pt==sk_x_alpha_x_G_pt)

def main():
	spend_pk = scalarmult_base(spend_sk)
	print('spend pk:',spend_pk)
	view_pk = scalarmult_base(view_sk)
	print('view pk:',view_pk)

	public_address(spend_pk, view_pk)

if __name__ == '__main__':
	# test_sig_1()
	# test_curve()
	# test_curve1()
	# test_encode_decode()
	# test_add_mult_int()
	test_Schnorr_Signatures()
	# test_AOS_Signature()
	# test_Borromean_Signature_single()
	# test_Borromean_Signature_batch()
