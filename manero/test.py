import my_ed25519_2 as ed25519
import binascii
import base58

# https://monero.stackexchange.com/questions/2290/why-how-does-monero-generate-public-ed25519-keys-without-using-the-standard-publ
def publicKey(sk):
    # a = ed25519.decodeint(sk)
    # A = ed25519.scalarmult(ed25519.B,a)
    # return ed25519.encodeint(A)
    return ed25519.publickey(sk)

def test1():
    # spendkey_hex = b'd17f7ee37fc904cd04692a0db2a8aa003008de6865d7b0ed7c1515b9892cca03'
    spendkey_hex = b'd17f7ee37fc904cd04692a0db2a8aa003008de6865d7b0ed7c1515b9892cca03'
    sk = binascii.unhexlify(spendkey_hex)
    # print(sk)
    pk = publicKey(sk)
    print('yours  : ',binascii.hexlify(pk))

def test2():
    data = b'122817dc38531a3e'
    for i in range(0,12):
        data = base58.b58encode(data)
        print(data)


def main():
    test2()


if __name__ == '__main__':
    main()