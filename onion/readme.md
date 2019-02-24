# Onion Service

## Onion Address generation

Get the RSA private key's public key, convert it to DER-encoded form, calculate the SHA-1 hash of that, take only the first half of it, and convert that base-16 value to base-32. [*](https://www.reddit.com/r/TOR/comments/381tvu/check_if_private_key_corresponds_to_onion_address/)


```shell
U=$(openssl rsa -in a.pem -pubout -outform DER | tail -c +23 | shasum | head -c 20 | python -c "import base64,sys; print base64.b32encode(sys.stdin.readline().strip('\n').decode('hex')).lower()"); echo "http://${U}.onion"
```

tail -c +23: https://www.computerhope.com/unix/utail.htm



# notes
https://stackoverflow.com/questions/28583565/str-object-has-no-attribute-decode-python-3-error

[encode & decode of python2 and 3 are different.](https://stackoverflow.com/questions/9641440/convert-from-ascii-string-encoded-in-hex-to-plain-ascii)

[sha 1](https://pycryptodome.readthedocs.io/en/latest/src/hash/sha1.html)
[RSA](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html)
[codecs document](https://docs.python.org/3/library/codecs.html)
[ed25519](https://github.com/warner/python-ed25519)

