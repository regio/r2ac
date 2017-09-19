import time
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

key  = "PATASDEGALINHA2017CHAPOLIN123456";
text = "You with your switching sides and your walk-by lies and humiliation0000000000000"
length = len(text)
print length
iv = Random.new().read(AES.block_size)


# Encryption
t1 = time.time()
encryption_suite = AES.new(key, AES.MODE_ECB, iv)
cipher_text = encryption_suite.encrypt(text)
t2 = time.time()

# Decryption
t3 = time.time()
decryption_suite = AES.new(key, AES.MODE_ECB, iv)
plain_text = decryption_suite.decrypt(cipher_text)
t4 = time.time()

print "Encryption"
diff = t2-t1
print '{0:.25f}'.format(diff)
print "Decryption"
diff = t4-t3
print '{0:.25f}'.format(diff)

t5 = time.time()
rs = SHA256.new(text).hexdigest()
encryption_suite = AES.new(key, AES.MODE_ECB, iv)
cipher_text = encryption_suite.encrypt(text)
cipher_text = encryption_suite.encrypt(rs)
t6 = time.time()

print "Enc+SHA"
diff = t6-t5
print '{0:.25f}'.format(diff)
