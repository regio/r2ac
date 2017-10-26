import chainFunctions
import criptoFunctions
import sys
import os
import time
import hashlib
import logging
import logging.config
import DeviceKeyMapping
import DeviceInfo

from flask import Flask, request
from os import listdir, urandom
from os.path import isfile, join

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

app = Flask(__name__)
peers = []
IoTLedger = []
genKeysPars = []

g = chainFunctions.getGenesisBlock()
IoTLedger.append(g)

# each file read will be mapped to an IoT Ledger Block
def bootstrapChain():

    folder = "./keys/"
    publicK= []

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("Gateway_private"):
                fl = open(folder+f, 'r')
                gwPvt = fl.read()

            if f.startswith("Gateway_public"):
                fl = open(folder+f, 'r')
                gwPub = fl.read()

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("public"):
                publicK.append(folder+f)
                fl = open(folder+f, 'r')
                key = fl.read() 
                newBlock = chainFunctions.generateNextBlock(f, key, getLatestBlock(), gwPvt)
                addIoTBlock(newBlock)

def addIoTBlock(newIoTBlock):
    global IoTLedger
    # if (isValidNewBlock(newBlock, getLatestBlock())):
    logger.debug("---------------------------------------")
    logger.debug("[addBlock] Chain size:"+str(len(IoTLedger)))
    logger.debug("IoT Block Size:"+str(len(str(newIoTBlock))))
    logger.debug("BH - index:"+str(newIoTBlock.index))
    logger.debug("BH - previousHash:"+str(newIoTBlock.previousHash))
    logger.debug("BH - timestamp:"+str(newIoTBlock.timestamp))
    logger.debug("BH - hash:"+str(newIoTBlock.hash))
    logger.debug("BH - publicKey:"+str(newIoTBlock.publicKey))

    IoTLedger.append(newIoTBlock)

def getLatestBlock():
    global IoTLedger
    return IoTLedger[len(IoTLedger) - 1]

def getLatestBlockLedger(blk):
        return blk.blockLedger[len(blk.blockLedger) - 1]

def findBlock(key):
    global IoTLedger
    for b in IoTLedger:
        if(b.publicKey == key):
            return b
    return False

def findAESKey(devPubKey):
    global genKeysPars
    for b in genKeysPars:
        if(b.publicKey == devPubKey):
            return b.AESKey
    return False

#############################################################################
#############################################################################
######################    CRIPTOGRAPHY       ################################
#############################################################################
#############################################################################

def generateAESKey(devPubKey):
    global genKeysPars
    randomAESKey = os.urandom(32) # AES key: 256 bits
    encKey = criptoFunctions.encryptRSA2(devPubKey, randomAESKey)
    obj = DeviceKeyMapping.DeviceKeyMapping(devPubKey,encKey)
    genKeysPars.append(obj)
    return encKey

#############################################################################
#############################################################################
######################        Routes         ################################
#############################################################################
#############################################################################
@app.route('/listPeers', methods=['POST'])
def listPeers():
    print(str(peers))
    return str(peers)


@app.route('/startBootStrap', methods=['POST'])
def startBootStrap():
    bootstrapChain()
    return "ok"

# This operation is called at very first step in the device communication
# In case the Device is already at IoTLedger the gateway will send a AES Key.
@app.route('/auth', methods=['POST'])
def auth():
	encKey =  ''
	t1 = time.time()
	content = request.get_json()
	devPubKey = content['publicKey']
	print(devPubKey)
	blk = findBlock(devPubKey)
	if(blk != False and blk.index > 0):
	        encKey = generateAESKey(blk.publicKey)

	t2 = time.time()
	logger.debug("=====1=====>time to generate key: "+'{0:.12f}'.format((t2-t1)*1000))
	logger.debug("Encrypted key:"+encKey)
	
	return encKey

# funcao que recebe um dado encryptado do Device, a chave publica e a assinatura do dispositivo.
# busca o bloco identificado pela chave publica
# decripta o dado (com a chave publica busca no bloco)
# decripta a assinatura (com a chave publica do bloco)
# cria um novo "bloco" de informacacao
# assina o bloco de informacao primeiro com a chave do device depois com a chave do gateway
# append o bloco de informacao ao Bloco da blockchain.
@app.route('/info', methods=['POST'])
def info():
    content = request.get_json()
    devPublicKey = content['publicKey']
    encryptedObj = content['EncObj']
    blk = findBlock(devPubKey)

    if(blk != False and blk.index > 0):
        devAESKey = findAESKey(devPublicKey)
        #plainObject vira com [Assinatura + Time + Data]
        plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)
        singature = plainObject[:len(devPubKey)]
        time = plainObject[len(devPubKey):len(devPubKey)+16] #16 is the timestamp lenght
        deviceData = plainObject[len(devPubKey)+16:]
        deviceInfo = DeviceInfo.DeviceInfo(signature, time, deviceData)

        nextInt = blk.blockLedger[len(blk.blockLedger) - 1].index + 1
        signData = criptoFunctions.signInfo(gwPvt, deviceInfo)

        #code responsible to create the hash between Info nodes.
        prevInfoHash = criptoFunctions.calculateHashForBlockLedger(getLatestBlockLedger(blk))
        newBlockLedger = BlockLedger.BlockLedger(nextInt, prevInfoHash, time, deviceInfo, signData) # gera um pacote do tipo Info com o deviceInfo como conteudo
        
        # aqui sera feito o algoritmo de consenso para o BlockLedger

        blk.blockLedger.append(newBlockLedger)

        for peer in peers:
            #print("******[AddingInfo]-Sending:"+blk.publicKey + ',' + str(gatewayInfo))
            #peer.send(blk.publicKey + ',' + str(gatewayInfo).encode("UTF-8"))
            print "Escrever aqui o codigo para enviar apenas o newBlockLedger para os peers"

        return "Loucurinha!"


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def main():
	bootstrapChain()
	def runApp():
		app.run(host=sys.argv[1], port=3001, debug=True)
	runApp()    


if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <computer IP> <port>")
        quit()
    os.system("clear")
    main()