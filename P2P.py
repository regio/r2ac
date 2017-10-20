import traceback
import sys
import socket
from flask import Flask, request
from os import listdir
from os.path import isfile, join
from Crypto import Random
import os
import threading
from Crypto.Cipher import AES
import time
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import hashlib
import ctypes

memfield = (ctypes.c_char_p).from_address(0x0A7F03E4)
app = Flask(__name__)
peers = []
blockchain = []

gwPvt = ""
gwPub = ""

tempDEBUGData = ""
tempDEBUGKey = ""
tempDEBUGSinature = ""
tempDEBUGTimestamp = ""

def createHash(key):
    shaFunc = hashlib.sha256()
    shaFunc.update((key).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

def bootstrapChain():
    folder = "./keys/"
    publicK = []

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("public"):
                publicK.append(folder+f)
                fl = open(folder+f, 'r')
                key = fl.read()
                addBlock(newBlock)

            if f.startswith("Gateway_private"):
                fl = open(folder+f, 'r')
                gwPvt = fl.read()

            if f.startswith("Gateway_public"):
                fl = open(folder+f, 'r')
                gwPub = fl.read()

@app.route('/addBlock', method=['POST'])
def addBlock():
    global memfield
    print("current thread: " + str(threading.current_thread()))
    memfield = memfield + 'oi, '
    for peer in peers:
        peer.send(str(memfield).encode("UTF-8"))

def isValidNewBlock(newBlock, previousBlock):
    if(previousBlock.index+1 != newBlock.index):
        print("Invalid index block")
        return False
    elif(previousBlock.hash != newBlock.previousHash):
        print("Invalid previousHash")
        return False
        print("Calculated new Block hash invalid")
        return False
    return True

def getLatestBlock():
    global memfield
    return memfield[len(memfield) - 1]

def getLatestInfo(blk):
        return blk.info[len(blk.info) - 1]

def findBlock(key):
    global memfield
    for b in memfield:
        if(b.publicKey == key):
            return b
    return False

@app.route('/addPeer', methods=['POST'])
def addPeer():
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    content = request.get_json()
    peer.connect((content['host'], int(content['port'])))
    peers.append(peer)

    return 'added\n'

def encryptRSA2(key, text):
    k = RSA.importKey(key)
    enc = k.encrypt(text, 42)[0]
    enc64 = base64.b64encode(enc)
    return enc64

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

def authenticate(publicKey, somedata):
    global tempDEBUGKey
    randomKey = os.urandom(32)
    tempDEBUGKey = randomKey
    encKey = encryptRSA2(publicKey, randomKey)
    return encKey

def signInfo(gwPvtKey, data):
    signer = PKCS1_v1_5.new(gwPvtKey)
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

@app.route('/auth', methods=['POST'])
def auth():
    global tempDEBUGKey
    info = ''
    t1 = time.time()
    content = request.get_json()
    data = content['data']
    devPubKey = content['publicKey']
    blk = findBlock(devPubKey)
    if(blk != False and blk.index > 0):
        info = authenticate(blk.publicKey, data)

    t2 = time.time()
    print("=====1=====>time to generate key: "+'{0:.12f}'.format((t2-t1)*1000))
    print("Random key:"+base64.b64encode(tempDEBUGKey))

    global gwPvt
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    gwPvt, public = key, key.publickey()
    return info

@app.route('/info', methods=['POST'])
def info():
    global tempDEBUGData
    global tempDEBUGKey
    global tempDEBUGTimestamp
    content = request.get_json()
    encryptedData = content['data']
    devPubKey = content['publicKey']
    deviceSignatureCrypt = content['signature']
    blk = findBlock(devPubKey)
    encryptedData = tempDEBUGData
    deviceSignatureCrypt = tempDEBUGData
    devPubKey = tempDEBUGKey
    devDataTimeStamp = tempDEBUGTimestamp
    tinit = time.time()

    if(blk != False and blk.index > 0):
        plainData = decryptAES(encryptedData, devPubKey)
        plainSign = decryptAES(deviceSignatureCrypt, devPubKey)
        # tdec = time.time()
        print(blk.info[len(blk.info) - 1].index)
        nextInt = blk.info[len(blk.info) - 1].index + 1
        signData = signInfo(gwPvt, plainData)
        return signData

@app.route('/debugEncAES', methods=['POST'])
def debugEncAES():
    global tempDEBUGKey
    global tempDEBUGData
    global tempDEBUGSinature
    global tempDEBUGTimestamp
    content = request.get_json()
    data = content['data']
    d = encryptAES(data, tempDEBUGKey)
    tempDEBUGData = d
    tempDEBUGSinature = signInfo(gwPvt, d)
    tempDEBUGTimestamp = time.time()
    print("Your encrypted data is:"+d)
    print("Your siganture is:" + tempDEBUGSinature)
    return tempDEBUGData

@app.route('/debugDecAES', methods=['POST'])
def debugDecAES():
    global tempDEBUGKey
    global tempDEBUGData
    d = decryptAES(tempDEBUGData, tempDEBUGKey)
    print("Your plain data is:"+d)
    return d

@app.route('/listInfos', methods=['POST'])
def listInfos():
    global memfield
    infos = []
    for block in memfield:
        infos.append(block.info)
    return str(infos)

@app.route('/listPeers', methods=['POST'])
def listPeers():
    print(str(peers))
    return str(peers)

@app.route('/startBootStrap', methods=['POST'])
def startBootStrap():
    global memfield
    bootstrapChain()

    return ""

@app.route('/listBlocks', methods=['POST'])
def listBlocks():
    global memfield
    # print ("[listBlocks]total of blocks:" + str(len(memfield)))
    print("current thread: " + str(threading.current_thread() + '; memfield: ' + memfield))
    return str(memfield)

def newBlock(data):
    global memfield

def newInfo(data, t1):
    check = False
    blk = findBlock(data[0])
    if(blk != False):
        for info in blk.info:
            if(info.index == newInfo.index):
                check = True
                break

        if(check == False):
            blk.info.append(newInfo)
            print("time to add new info: " + '{0:.12f}'.format((time.time() - t1) * 1000))

        for peer in peers:
            peer.send(blk.publicKey + ',' + str(newInfo).encode("UTF-8"))
    else:
        print ("not found:Block:" + data[0])

def main():
    def runApp():
        app.run(host=sys.argv[1], port=3001, debug=True)

    class server(threading.Thread):
        def __init__(self, name):
            threading.Thread.__init__(self)
            self.name = name

        def run(self):
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((sys.argv[1], int(sys.argv[2])))
            s.listen(1)
            helper = 0

            while True:
                c, addr = s.accept()
                client = clienthandler('client' + str(helper), c)
                client.start()
                client.join()
                helper += 1

    class clienthandler(threading.Thread):
        def __init__(self, name, c):
            threading.Thread.__init__(self)
            self.name = name
            self.c = c

        def run(self):
            global memfield
            try:
                tprevious = time.time()
                while True:
                    data = self.c.recv(500).decode("UTF-8")
                    t1 = time.time()
                    if not data:
                        break
                    else:
                        # aux = str(data).split(',')
                        # print ("===>received size:"+str(len(aux)))
                        # if(len(aux) > 8):
                        #     print ("=====>received a new block")
                        addBlock(data)
                        # else:
                        #     print ("=====>received a new info")
                        #     newInfo(aux, t1)

                    del data
                    # del aux
                    tprevious = t1

            except Exception as e:
                print ("something went wrong... closing connection:")
                print(e)
                exc_info = sys.exc_info()
                traceback.print_exception(*exc_info)
                del exc_info
                print ("done error")
                self.c.close()

    sv = server('server')
    sv.start()
    runApp()
    sv.join()

if __name__ == '__main__':
    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python P2P.py <computer IP> <port>")
        quit()
    main()
