import hashlib
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def calculateHash(index, previousHash, timestamp, key):
    shaFunc = hashlib.sha256()
    shaFunc.update((str(index)+str(previousHash)+str(timestamp)+key).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

def calculateHashForBlock(block):
    return calculateHash(block.index, block.previousHash, block.timestamp, block.publicKey)

def calculateHashForBlockLedger(info):
	shaFunc = hashlib.sha256()
	shaFunc.update((str(info.index)+str(info.previousHash)+str(info.timestamp)+str(info.data)+str(info.signature)).encode('utf-8'))
	val = shaFunc.hexdigest()
	return val

# encrypted data returns in base64
def encryptRSA2(key, text):
    k = RSA.importKey(key)
    enc = k.encrypt(text, 42)[0]
    enc64 = base64.b64encode(enc)
    return enc64

# data should be sent in base64
def decryptRSA2(key, text):
    k = RSA.importKey(key)
    deb = base64.b64decode(text)
    data = k.decrypt(deb)
    return data

def encryptAES(text, k):
    cypher = AES.new(k, AES.MODE_ECB, "4242424242424242")
    cy = cypher.encrypt(text)
    enc64 = base64.b64encode(cy)
    return enc64

def decryptAES(text, k):
    enc = base64.b64decode(text)
    decryption_suite = AES.new(k, AES.MODE_ECB, "4242424242424242")
    plain_text = decryption_suite.decrypt(enc)
    return plain_text	

def signInfo(gwPvtKey, data):
	k = RSA.importKey(gwPvtKey)
	signer = PKCS1_v1_5.new(k)
	digest = SHA256.new()
	digest.update(data)
	s = signer.sign(digest)
	sinature = base64.b64encode(s)
	return sinature

def signVerify(data, signature, gwPubKey):
    signer = PKCS1_v1_5.new(gwPubKey)
    digest = SHA256.new()
    digest.update(data)
    signaturerOr = base64.b64decode(signature)
    result = signer.verify(digest, signaturerOr)
    return result