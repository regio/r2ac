# rodar a sequencia:
# 1 - iniciar a transacao, e gerar a chave criptografica
# 3 - neste passo o dado sera encriptado com  a chave gerada anteriormente
# (para simular que o dispositivo, recebeu a chave, e encriptou alguma coisa)
# 2 - recebe o dado do dispositivo, assina e insere a informacao na blockchain.

import chainFunctions
import P2P
import criptoFunctions
import os
import base64
import time
import socket
import Info
import Block

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, request
from os import listdir
from os.path import isfile, join

app = Flask(__name__)

sockets = []

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

def bootstrapChain():

    folder = "./keys/"
    publicK= []

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
    if (isValidNewBlock(newBlock, getLatestBlock())):
        blockchain.append(newBlock)

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
    return blockchain[len(blockchain) - 1]

def findBlock(key):
    for b in blockchain:
        if(b.publicKey == key):
            #print "key found"
            return b

    return False

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
    ti = time.time()
    content = request.get_json()
    encryptedData = content['data']
    devPubKey = content['publicKey']
    deviceSignatureCrypt = content['signature']
    blk = findBlock(devPubKey)
#DEBUG Sector
    encryptedData = tempDEBUGData
    deviceSignatureCrypt = tempDEBUGData
    devPubKey = tempDEBUGKey
#DEBUG
    tinit = time.time()

    if(blk != False and blk.index > 0):
        plainData = decryptAES(encryptedData, devPubKey) # decripta o dado recebido
        plainSign = decryptAES(deviceSignatureCrypt, devPubKey) # decripta a assinatura recebida
        tdec = time.time()
        print(blk.info.index)
        nextInt = blk.info.index+1
        deviceInfo = Info.Info(nextInt, plainData, plainSign) # gera um pacote do tipo Info com o painData como conteudo
        signData = signInfo(gwPvt, str(deviceInfo))
        gatewayInfo = Info.Info(nextInt, deviceInfo, signData) # gera um pacote do tipo Info com o deviceInfo como conteudo
        blk.info = gatewayInfo # append o Info para o bloco da blockchain.

        tf = time.time()
        print("=====2=====>time to add block: " + '{0:.12f}'.format((tf - ti) * 1000))
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
    content = request.get_json()
    data = content['data']  #pega o dado que sera encriptado
    d = encryptAES(data, tempDEBUGKey)   #encripta o dado com a chave que foi gerada no metodo de autenticacao (1)
    tempDEBUGData = d    # guarda o dado encriptado para posteriormente ser inserido na blockchain
    tempDEBUGSinature = signInfo(gwPvt, d)   # assina o dado gerado para mandar para o metodo de insercao no bloco da blockchain (3)
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


def startServer():
    app.run(host='localhost', port=3001, debug=True)
    #app.run(host='10.32.175.195', port=3001, debug=True)#Pi@Pucrs
    

def main():
    print("main starting")
    bootstrapChain()
    startServer()


if __name__ == "__main__":main() ## with if
