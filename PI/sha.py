import time
#from time import time
from Crypto.Hash import SHA256

def micros():
    return time.time()

def millis():
        return int(round(time.time() * 1000))

text = "You with your switching sides and your walk-by lies and humiliation0000000000000"

vi = time.time()
#print millis()
rs = SHA256.new(text).hexdigest()
vf = time.time()
#print millis()
dif=vf-vi

print "SHA"
print '{0:.25f}'.format(dif)
