import base64
import time

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def signInfo(gwPvtKey, data):
    signer = PKCS1_v1_5.new(gwPvtKey)
    digest = SHA256.new()
    digest.update(data)
    s = signer.sign(digest)
    sinature = base64.b64encode(s)
    return sinature


random_generator = Random.new().read
key = RSA.generate(1024, random_generator)
private, public = key, key.publickey()
t1 = time.time()
x = signInfo(private, "You with your switching sides and your walk-by lies and humiliation0000000000000")
t2 = time.time()
print "time to sign Info: "+'{0:.12f}'.format((t2-t1)*1000)
print x