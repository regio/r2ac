import Pyro4
import socket
import logging.config
import os
import sys
import time
from os import listdir
from os.path import isfile, join

from flask import Flask, request

import BlockLedger
import DeviceInfo
import DeviceKeyMapping
import chainFunctions
import criptoFunctions

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

app = Flask(__name__)
peers = []
IoTLedger = []
genKeysPars = []

gwPvt = ""
gwPub = ""

g = chainFunctions.getGenesisBlock()
IoTLedger.append(g)


# each file read will be mapped to an IoT Ledger Block
def bootstrapChain():
    global gwPub
    global gwPvt

    folder = "./keys/"
    publicK = []

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("Gateway_private"):
                fl = open(folder + f, 'r')
                gwPvt = fl.read()

            if f.startswith("Gateway_public"):
                fl = open(folder + f, 'r')
                gwPub = fl.read()

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("public"):
                publicK.append(folder + f)
                fl = open(folder + f, 'r')
                key = fl.read()
                newBlock = chainFunctions.generateNextBlock(f, key, getLatestBlock(), gwPvt)
                addIoTBlock(newBlock)


def addIoTBlock(newIoTBlock):
    global IoTLedger
    # if (isValidNewBlock(newBlock, getLatestBlock())):
    logger.debug("---------------------------------------")
    logger.debug("[addBlock] Chain size:" + str(len(IoTLedger)))
    logger.debug("IoT Block Size:" + str(len(str(newIoTBlock))))
    logger.debug("BH - index:" + str(newIoTBlock.index))
    logger.debug("BH - previousHash:" + str(newIoTBlock.previousHash))
    logger.debug("BH - timestamp:" + str(newIoTBlock.timestamp))
    logger.debug("BH - hash:" + str(newIoTBlock.hash))
    logger.debug("BH - publicKey:" + str(newIoTBlock.publicKey))

    IoTLedger.append(newIoTBlock)


def addBlockLedger(IoTBlock, newBlockLedger):
    IoTBlock.blockLedger.append(newBlockLedger)


def getLatestBlock():
    global IoTLedger
    return IoTLedger[len(IoTLedger) - 1]


def getLatestBlockLedger(blk):
    return blk.blockLedger[len(blk.blockLedger) - 1]


def findBlock(key):
    global IoTLedger
    for b in IoTLedger:
        if (b.publicKey == key):
            return b
    return False


def findAESKey(devPubKey):
    global genKeysPars
    for b in genKeysPars:
        if (b.publicKey == devPubKey):
            return b.AESKey
    return False


def sendBlockLedgerToPeers(blockLedger):
    global peers
    for peer in peers:
        # print("******[AddingInfo]-Sending:"+blk.publicKey + ',' + str(gatewayInfo))
        # peer.send(blk.publicKey + ',' + str(gatewayInfo).encode("UTF-8"))
        print "Escrever aqui o codigo para enviar apenas o newBlockLedger para os peers"


def sendIoTBlockToPeers(IoTBlock):
    global peers
    for peer in peers:
        # print("******[AddingInfo]-Sending:"+blk.publicKey + ',' + str(gatewayInfo))
        # peer.send(blk.publicKey + ',' + str(gatewayInfo).encode("UTF-8"))
        print "Escrever aqui o codigo para enviar apenas o newIoTBlock para os peers"


def getMyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP


#############################################################################
#############################################################################
######################    CRIPTOGRAPHY       ################################
#############################################################################
#############################################################################

def generateAESKey(devPubKey):
    global genKeysPars
    randomAESKey = os.urandom(32)  # AES key: 256 bits
    obj = DeviceKeyMapping.DeviceKeyMapping(devPubKey, randomAESKey)
    genKeysPars.append(obj)
    return randomAESKey


#############################################################################
#############################################################################
######################        Routes         ################################
#############################################################################
#############################################################################
@app.route('/listPeers', methods=['POST'])
def listPeers():
    print(str(peers))
    return str(peers)


# This operation is called at very first step in the device communication
# In case the Device is already at IoTLedger the gateway will send a AES Key.
@app.route('/auth', methods=['POST'])
def auth():
    aesKey = ''
    t1 = time.time()
    content = request.get_json()
    devPubKey = content['publicKey']
    print(devPubKey)
    blk = findBlock(devPubKey)
    if (blk != False and blk.index > 0):
        aesKey = findAESKey(devPubKey)
        if (aesKey == False):
            aesKey = generateAESKey(blk.publicKey)
    else:
        print("The device IoT Block Ledger is not present.")
        print("We should write the code to create a new block here...")

    encKey = criptoFunctions.encryptRSA2(devPubKey, aesKey)
    t2 = time.time()
    logger.debug("=====1=====>time to generate key: " + '{0:.12f}'.format((t2 - t1) * 1000))
    logger.debug("Encrypted key:" + encKey)

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
    global gwPvt
    content = request.get_json()
    devPublicKey = content['publicKey']
    encryptedObj = content['EncObj']
    blk = findBlock(devPublicKey)

    if (blk != False and blk.index > 0):
        devAESKey = findAESKey(devPublicKey)
        if (devAESKey != False):
            # plainObject vira com [Assinatura + Time + Data]
            plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)

            signature = plainObject[:len(devPublicKey)]
            time = plainObject[len(devPublicKey):len(devPublicKey) + 16]  # 16 is the timestamp lenght
            deviceData = plainObject[len(devPublicKey) + 16:]
            deviceInfo = DeviceInfo.DeviceInfo(signature, time, deviceData)

            nextInt = blk.blockLedger[len(blk.blockLedger) - 1].index + 1
            signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))

            # code responsible to create the hash between Info nodes.
            prevInfoHash = criptoFunctions.calculateHashForBlockLedger(getLatestBlockLedger(blk))
            newBlockLedger = BlockLedger.BlockLedger(nextInt, prevInfoHash, time, deviceInfo,
                                                     signData)  # gera um pacote do tipo Info com o deviceInfo como conteudo

            addBlockLedger(blk, newBlockLedger)
            sendBlockLedgerToPeers(newBlockLedger)

            return "Loucurinha!"
        return "key not found"


#############################################################################
#############################################################################
######################          R2AC Class   ################################
#############################################################################
#############################################################################


# @Pyro4.expose
# @Pyro4.behavior(instance_mode="single")
# class R2ac(object):
#     def __init__(self):
#         print("R2AC initialized")
#
#     def info(self):
#         global gwPvt
#         content = request.get_json()
#         devPublicKey = content['publicKey']
#         encryptedObj = content['EncObj']
#         blk = findBlock(devPublicKey)
#
#         if (blk != False and blk.index > 0):
#             devAESKey = findAESKey(devPublicKey)
#             if (devAESKey != False):
#                 # plainObject vira com [Assinatura + Time + Data]
#                 plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)
#
#                 signature = plainObject[:len(devPublicKey)]
#                 time = plainObject[len(devPublicKey):len(devPublicKey) + 16]  # 16 is the timestamp lenght
#                 deviceData = plainObject[len(devPublicKey) + 16:]
#                 deviceInfo = DeviceInfo.DeviceInfo(signature, time, deviceData)
#
#                 nextInt = blk.blockLedger[len(blk.blockLedger) - 1].index + 1
#                 signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))
#
#                 # code responsible to create the hash between Info nodes.
#                 prevInfoHash = criptoFunctions.calculateHashForBlockLedger(getLatestBlockLedger(blk))
#                 newBlockLedger = BlockLedger.BlockLedger(nextInt, prevInfoHash, time, deviceInfo,
#                                                          signData)  # gera um pacote do tipo Info com o deviceInfo como conteudo
#
#                 addBlockLedger(blk, newBlockLedger)
#                 sendBlockLedgerToPeers(newBlockLedger)
#
#                 return "Loucurinha!"
#             return "key not found"
#
#     def auth(self):
#         aesKey = ''
#         t1 = time.time()
#         content = request.get_json()
#         devPubKey = content['publicKey']
#         print(devPubKey)
#         blk = findBlock(devPubKey)
#         if (blk != False and blk.index > 0):
#             aesKey = findAESKey(devPubKey)
#             if (aesKey == False):
#                 aesKey = generateAESKey(blk.publicKey)
#         else:
#             print("The device IoT Block Ledger is not present.")
#             print("We should write the code to create a new block here...")
#
#         encKey = criptoFunctions.encryptRSA2(devPubKey, aesKey)
#         t2 = time.time()
#         logger.debug("=====1=====>time to generate key: " + '{0:.12f}'.format((t2 - t1) * 1000))
#         logger.debug("Encrypted key:" + encKey)
#
#         return encKey


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def main():
    bootstrapChain()

    # Pyro4.config.HOST = str(getMyIP())
    # Pyro4.Daemon.serveSimple(
    #     {
    #         R2ac: "r2ac"
    #     },
    #     ns=False)

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
