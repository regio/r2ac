import time
import RSA
from Crypto.Hash import SHA256

RSA_Others_Public_Key = [5723, 5]
RSA_Own_Private_Key = [5723, 3341];


text = "You with your switching sides and your walk-by lies and humiliation0000000000000"


ti =  time.time()
###########################################
enc = RSA.rsa_encrypt(text, RSA_Others_Public_Key)
denc = RSA.rsa_decrypt(enc, RSA_Own_Private_Key)
###########################################
tf = time.time()
dif = tf-ti

print "RSA-enc+dec"
print '{0:.25f}'.format(dif)

