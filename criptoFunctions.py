import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

iv = "4242424242424242"
BS = 32
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

def calculateHash(index, previousHash, timestamp, key):
    """ Calculate the hash of 4 infos concatenated index+previousHash+timestamp+key\n
        @param index - block index\n
        @param previousHash - previous block hash\n
        @param timestamp - generation time of the block\n
        @param key - key of the block\n
        @return val - hash of it all
    """
    shaFunc = hashlib.sha256()
    shaFunc.update((str(index) + str(previousHash) + str(timestamp) + str(key)).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val


def calculateHashForBlock(block):
    """ Receive a block and calulates his hash using the index, previous block hash, timestamp and the public key of the block\n
        @return result of calculateHash function - a hash
    """
    return calculateHash(block.index, block.previousHash, block.timestamp, block.publicKey)


def calculateTransactionHash(blockLedger):
    """ Receive a transaction and calculate the hash\n
        @param blockLedger - transaction object\n
        @return hash of (index + previousHash + timestamp + data + signature) UTF-8
    """
    shaFunc = hashlib.sha256()
    shaFunc.update((str(blockLedger.index) + str(blockLedger.previousHash) + str(blockLedger.timestamp) + str(
        blockLedger.data) + str(blockLedger.signature)).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

def encryptRSA(key, text):
    """ Receive a key and a text and encrypt it on Base 64\n
        @param key - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return enc64 - text encrypted
        @return 10 in case of error with the key
    """
    try:
        k = RSA.importKey(key)
    except (ValueError, IndexError, TypeError):
        return False

    enc = k.encrypt(text, 42)[0]
    enc64 = base64.b64encode(enc)
    return enc64    

def decryptRSA(key, text):
    """ Receive a key and a text and decrypt the text with the key using Base 64 \n
        @param key - key to make te decrypt\n
        @param text - text encrypted\n
        @return data - text decrypted
    """
    try:
        k = RSA.importKey(key)
    except (ValueError, IndexError, TypeError):
        return False
        
    deb = base64.b64decode(text)
    data = k.decrypt(deb)
    return data

def encryptRSA2(key, text):
    """ Receive a key and a text and encrypt it on Base 64\n
        @param key - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return enc64 - text encrypted
    """
    k = RSA.importKey(key)
    enc = k.encrypt(text, 42)[0]
    enc64 = base64.b64encode(enc)
    return enc64

def decryptRSA2(key, text):
    """ Receive a key and a text and decrypt the text with the key using Base 64 \n
        @param key - key to make te decrypt\n
        @param text - text encrypted\n
        @return data - text decrypted
    """
    k = RSA.importKey(key)
    deb = base64.b64decode(text)
    data = k.decrypt(deb)
    return data


def encryptAES(text, k):
    """ Receive a key and a text and encrypt it on AES\n
        @param k - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return enc64 - text encrypted
    """
    cypher = AES.new(k, AES.MODE_CBC, iv)
    textPadded = pad(text)
    cy = cypher.encrypt(textPadded)
    enc64 = base64.b64encode(cy)
    return enc64


def decryptAES(text, k):
    """ Receive a key and a text and decrypt the text with the key using AES \n
        @param k - key to make te decrypt\n
        @param text - text encrypted\n
        @return plainTextUnpadded - text decrypted
    """
    enc = base64.b64decode(text)
    decryption_suite = AES.new(k, AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(enc)
    plainTextUnpadded = unpad(plain_text)
    return plainTextUnpadded


def signInfo(gwPvtKey, data):
    """ Sign some data with the peer's private key\n 
        @param gwPvtKey - peer's private key\n
        @param data - data to sign\n
        @return sinature - signature of the data maked with the private key
    """
    k = RSA.importKey(gwPvtKey)
    signer = PKCS1_v1_5.new(k)
    digest = SHA256.new()
    digest.update(data.encode('utf-8')) #added encode to support python 3 , need to evluate if it is still working
    #digest.update(data)
    s = signer.sign(digest)
    sinature = base64.b64encode(s)
    return sinature


def signVerify(data, signature, gwPubKey):
    """ Verify if a data sign by a private key it's unaltered\n
        @param data - data to be verified\n
        @param signature - singature of the data to be validated\n
        @param gwPubKey - peer's private key
    """
    pubKey = base64.b64decode(gwPubKey)
    k = RSA.importKey(pubKey)
    signer = PKCS1_v1_5.new(k)
    digest = SHA256.new()
    digest.update(data.encode('utf-8')) #added encode to support python 3 , need to evluate if it is still working
    #digest.update(data)
    signaturerOr = base64.b64decode(signature)
    result = signer.verify(digest, str(signaturerOr))
    return result

def generateRSAKeyPair():
    """ Generate a pair of RSA keys using RSA 1024\n
        @return pub, prv - public and private key
    """
    private = RSA.generate(1024)
    pubKey = private.publickey()
    prv = private.exportKey()
    pub = pubKey.exportKey()
    return pub, prv

