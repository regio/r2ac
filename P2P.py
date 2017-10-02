import traceback
import sys
import socket
from threading import *
from flask import Flask, request
import chainFunctions
from os import listdir
from os.path import isfile, join
import criptoFunctions
from Crypto import Random
import os
import Info
import threading
import Block
from Crypto.Cipher import AES
import time
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import hashlib

lock = threading.Condition()
app = Flask(__name__)
peers = []
blockchain = []

blockchain.append(chainFunctions.getGenesisBlock())

#gwPrv, gwPub, fileList = bootstrapChain()
gwPvt = ""
gwPub = ""

#DEBUG Stuff
# variaveis temporarias para armazenar o dado, a chave a a assinatura.                   pyChain.py:31
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
                newBlock = chainFunctions.generateNextBlock(f, key, getLatestBlock())
                addBlock(newBlock)

            if f.startswith("Gateway_private"):
                fl = open(folder+f, 'r')
                gwPvt = fl.read()

            if f.startswith("Gateway_public"):
                fl = open(folder+f, 'r')
                gwPub = fl.read()

def addBlock(newBlock):
    global blockchain
    # if (isValidNewBlock(newBlock, getLatestBlock())):
    print("current thread: " + str(threading.current_thread()))
    print ("[addBlock]Chain size:"+str(len(blockchain)))
    blockchain.append(newBlock)

    for peer in peers:
        for block in blockchain:
            #print("*********************Sending size:"+str(block.index)+"-"+str(len(str(block))) )
            #print("*********************Data Sent:"+str(block))
            if(len(str(block)) < 500):
                #data_string = pickle.dumps(block, -1)
                dif=500-len(str(block))-1
                pad = ''
                for x in range(0,dif):
                    pad=pad+"w"
                #print("*********************Sending size[padded]:"+str(len(str(block)+","+pad)) )
                peer.send(str(str(block)+","+pad).encode("UTF-8"))
            else:
                peer.send(str(block).encode("UTF-8"))
                #peer.send(data_string)
# def addBlock(newBlock):
#     if (isValidNewBlock(newBlock, getLatestBlock())):
#         blockchain.append(newBlock)

def isValidNewBlock(newBlock, previousBlock):
    if(previousBlock.index+1 != newBlock.index):
        print("Invalid index block")
        return False
    elif(previousBlock.hash != newBlock.previousHash):
        print("Invalid previousHash")
        return False
    elif(criptoFunctions.calculateHashForBlock(newBlock) != newBlock.hash):
        print("Calculated new Block hash invalid")
        return False
    return True

def getLatestBlock():
    global blockchain
    return blockchain[len(blockchain) - 1]

def getLatestInfo(blk):
        return blk.info[len(blk.info) - 1]

def findBlock(key):
    global blockchain
    #print ("Chain size:"+str(len(blockchain)))
    #print ("===========================================================")
    for b in blockchain:
        #print ("local:   --|"+b.publicKey+"|--")
        #print ("local hash:" + createHash(b.publicKey))
        #print ("recived: --|"+key+"|--")
        #print ("recei hash:" + createHash(key))
        if(b.publicKey == key):
            #print(b.publicKey + ', ' + key)
            #print ("key found")
            #print ("===========================================================")
            return b
    #print ("===========================================================")
    return False

@app.route('/listPeers', methods=['POST'])
def listPeers():
    print(str(peers))
    return str(peers)

@app.route('/addPeer', methods=['POST'])
def addPeer():
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    content = request.get_json()
    peer.connect((content['host'], int(content['port'])))
    peers.append(peer)
    # print("connected to host")
    # data = content['msg']
    # # msg = { 0, "0", 1465154705, "my genesis block!!", "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7" }
    # for peer in peers:
    #     # print(str(peer))
    #     peer.send((data).encode("UTF-8"))

    return 'added\n'

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
    #4242424242424242
    cypher = AES.new(k, AES.MODE_ECB, "4242424242424242")
    cy = cypher.encrypt(text)
    enc64 = base64.b64encode(cy)
    return enc64

def decryptAES(text, k):
    enc = base64.b64decode(text)
    #print "key:"+k
    decryption_suite = AES.new(k, AES.MODE_ECB, "4242424242424242")
    plain_text = decryption_suite.decrypt(enc)
    return plain_text

def authenticate(publicKey, somedata):
    global tempDEBUGKey
    randomKey = os.urandom(32)
    tempDEBUGKey = randomKey #Salva a chave que foi gerada randomicamente para uso posterior
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

#metodo que recebe dados e uma chave publica
# atraves da chave publica, busca na chain o bloco, e a chave publica que esta no bloco
# utliza a chave encontrada no bloco da chain para encriptar o dado.
@app.route('/auth', methods=['POST'])
def auth():
    global tempDEBUGKey
    info = ''
    t1 = time.time()
    content = request.get_json()
    data = content['data']
    devPubKey = content['publicKey']
    #print  "received key: "+devPubKey
    blk = findBlock(devPubKey)
    if(blk != False and blk.index > 0):
        info = authenticate(blk.publicKey, data)

    t2 = time.time()
    print("=====1=====>time to generate key: "+'{0:.12f}'.format((t2-t1)*1000))
    print("Random key:"+base64.b64encode(tempDEBUGKey))

#DEBUG
    global gwPvt
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    gwPvt, public = key, key.publickey()
#DEBUG
    return info

# funcao que recebe um dado encryptado, a chave publica e a assinatura do dispositivo.
# busca o bloco identificado pela chave publica
# decripta o dado (com a chave publica busca no bloco)
# decripta a assinatura (com a chave publica do bloco)
# cria um novo "bloco" de informacacao
# assina o bloco de informacao primeiro com a chave do device depois com a chave do gateway
# append o bloco de informacao ao Bloco da blockchain.
@app.route('/info', methods=['POST'])
def info():
    global tempDEBUGData
    global tempDEBUGKey
    global tempDEBUGTimestamp
    # ti = time.time()
    content = request.get_json()
    encryptedData = content['data']
    devPubKey = content['publicKey']
    deviceSignatureCrypt = content['signature']
    blk = findBlock(devPubKey)
#DEBUG Sector
    encryptedData = tempDEBUGData
    deviceSignatureCrypt = tempDEBUGData
    devPubKey = tempDEBUGKey
    devDataTimeStamp = tempDEBUGTimestamp
#DEBUG
    tinit = time.time()

    if(blk != False and blk.index > 0):
        plainData = decryptAES(encryptedData, devPubKey) # decripta o dado recebido
        plainSign = decryptAES(deviceSignatureCrypt, devPubKey) # decripta a assinatura recebida
        # tdec = time.time()
        print(blk.info[len(blk.info) - 1].index)
        nextInt = blk.info[len(blk.info) - 1].index + 1
        # deviceInfo = Info.Info(nextInt, plainData, plainSign) # gera um pacote do tipo Info com o painData como conteudo
        signData = signInfo(gwPvt, plainData)

        #code responsible to create the hash between Info nodes.
        prevInfoHash = criptoFunctions.calculateHashForInfo(getLatestInfo(blk))
        gatewayInfo = Info.Info(nextInt, prevInfoHash, devDataTimeStamp, plainData, signData) # gera um pacote do tipo Info com o deviceInfo como conteudo
        #gatewayInfo = Info.Info(nextInt, plainData, signData) # gera um pacote do tipo Info com o deviceInfo como conteudo
        blk.info.append(gatewayInfo) # append o Info para o bloco da blockchain.

        for peer in peers:
            #print("******[AddingInfo]-Sending:"+blk.publicKey + ',' + str(gatewayInfo))
            peer.send(blk.publicKey + ',' + str(gatewayInfo).encode("UTF-8"))

        # tf = time.time()
        # print("=====2=====>time to add block: " + '{0:.12f}'.format((tf - ti) * 1000))
        # updateChain()
        #print "==time to init: " + '{0:.12f}'.format((tinit - ti) * 1000)
        #print "==time to decrypt: " + '{0:.12f}'.format((tdec - tinit) * 1000)
        #print "==time to sign: " + '{0:.12f}'.format((tf - tdec) * 1000)
        return signData

# este metodo serve basicamente para simular o dispositivo que recebe a chave gerada randomincamente e encriptar alguma informacao.
@app.route('/debugEncAES', methods=['POST'])
def debugEncAES():
    global tempDEBUGKey
    global tempDEBUGData
    global tempDEBUGSinature
    global tempDEBUGTimestamp
    content = request.get_json()
    data = content['data']  #pega o dado que sera encriptado
    d = encryptAES(data, tempDEBUGKey)   #encripta o dado com a chave que foi gerada no metodo de autenticacao (1)
    tempDEBUGData = d    # guarda o dado encriptado para posteriormente ser inserido na blockchain
    tempDEBUGSinature = signInfo(gwPvt, d)   # assina o dado gerado para mandar para o metodo de insercao no bloco da blockchain (3)
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

@app.route('/listBlocks', methods=['POST'])
def listBlocks():
    global blockchain
    print ("[listBlocks]total of blocks:"+str(len(blockchain)))
    print("current thread: " + str(threading.current_thread()))
    # print(blockchain)
    # file = open("Chain.txt")
    # chain = file.read()
    # file.close()
    return str(blockchain)

@app.route('/listInfos', methods=['POST'])
def listInfos():
    global blockchain
    infos = []
    for block in blockchain:
        infos.append(block.info)
    return str(infos)

@app.route('/startBootStrap', methods=['POST'])
def startBootStrap():
    global blockchain
    print ("[1-startBootStrap]Chain size:"+str(len(blockchain)))
    bootstrapChain()
    # updateChain()
    print ("[2-startBootStrap]Chain size:"+str(len(blockchain)))

    return ""

# def updateChain():
#     global blockchain
#     file = open("Chain.txt", 'w')
#     file.seek(0)
#     file.truncate()
#     file.write(str(blockchain))
#     file.close()

def newBlock(data):
    global blockchain
    #print (data)
    print("current thread: " + str(threading.current_thread()))
    print ("=====>[newBlock]Chain size:"+str(len(blockchain)))
    #info = Info.Info(data[3], data[4], data[5])
    #blk = Block.Block(data[0], data[1], data[2], info, data[6], data[7])

    info = Info.Info(data[3], data[4], data[5], data[6], data[7])
    blk = Block.Block(data[0], data[1], data[2], info, data[8], data[9])
    if (findBlock(blk.publicKey) == False):
        print("=====>New block is appended to chain")
        lock.acquire()
        addBlock(blk)
        lock.notify_all()
        lock.release()
        # updateChain()
        # for peer in peers:
        #     for block in blockchain:
        #         peer.send(str(block).encode("UTF-8"))

def newInfo(data, t1):
    #tr = time.time()
    check = False
    blk = findBlock(data[0])
    if(blk != False):
        #newInfo = Info.Info(data[1], data[2], data[3])
        newInfo = Info.Info(data[1], data[2], data[3], data[4], data[5])
        for info in blk.info:
            if(info.index == newInfo.index):
                check = True
                break

        if(check == False):
            blk.info.append(newInfo)
            print("time to add new info: " + '{0:.12f}'.format((time.time() - t1) * 1000))
            # updateChain()

        for peer in peers:
            peer.send(blk.publicKey + ',' + str(newInfo).encode("UTF-8"))
    else:
        print ("not found:Block:" + data[0])

    #te = time.time()
    #difff = te-tr
    #print ("Time to update Block with recived info: " + str(difff))

def main():
    def runApp():
        app.run(host=sys.argv[1], port=3001, debug=True, threaded = True)

    class server(threading.Thread):
        def __init__(self, name):
            threading.Thread.__init__(self)
            self.name = name

        def run(self):
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((sys.argv[1], int(sys.argv[2])))
            s.listen(1)

            while True:
                c, addr = s.accept()
                client = clienthandler('client', c)
                client.start()
                client.join()

    class clienthandler(threading.Thread):
        def __init__(self, name, c):
            threading.Thread.__init__(self)
            self.name = name
            self.c = c
        
        def run(self):
            global blockchain
            try:
                tprevious = time.time()
                while True:
                    data = self.c.recv(500).decode("UTF-8")
                    #data_loaded = c.recv(1024)
                    #data = pickle.loads(data_loaded)
                    t1 = time.time()
                    print("time between requests: " + '{0:.12f}'.format(t1 - tprevious) * 1000)
                    if not data:
                        break
                    else:
                        aux = str(data).split(',')
                        #print ("#############################################################")
                        print ("===>received size:"+str(len(aux)))
                        #print ("===>received some data...:"+str(data))
                        #if(len(aux) == 8):
                        if(len(aux) > 8):
                            print ("=====>received a new block")
                            newBlock(aux)
                        else:
                            print ("=====>received a new info")
                            newInfo(aux, t1)

                    del data
                    del aux
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
