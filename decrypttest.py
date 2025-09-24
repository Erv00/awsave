
from Crypto.Cipher import ChaCha20
import sys, binascii

key = bytes([0x42]*32)
nonce = bytes([0x24]*12)

cipher = ChaCha20.new(key=key, nonce=nonce)
sys.stdout.buffer.write(cipher.decrypt(sys.stdin.buffer.read()))

