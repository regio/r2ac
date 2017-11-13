import pickle
import Pyro4
import socket
import logging.config
import os
import sys
import time
from os import listdir
from os.path import isfile, join
from flask import Flask
import BlockLedger
import DeviceInfo
import PeerInfo
import DeviceKeyMapping
import chainFunctions
import criptoFunctions

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

app = Flask(__name__)
peers = []
IoTLedger = []
genKeysPars = []
myURI = ""
gwPvt = ""
gwPub = ""
g = chainFunctions.getGenesisBlock()
IoTLedger.append(g)

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
    IoTLedger.append(newIoTBlock)

def addBlockLedger(IoTBlock, newBlockLedger):
    IoTBlock.blockLedger.append(newBlockLedger)

def getLatestBlock():
    global IoTLedger
    return IoTLedger[len(IoTLedger) - 1]

def getLatestBlockLedger(blk):
    return blk.blockLedger[len(blk.blockLedger) - 1]

def blockContainsBlockLedger(block, blockLedger):
    for bl in block.blockLedger:
        if bl == blockLedger:
            return True
    return False

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

def findPeer(peerURI):
    global peers
    for p in peers:
        if p.peerURI == peerURI:
            return True
    return False

def addBack(peer):
    global myURI
    obj = peer.object
    obj.addPeer(myURI)

def sendBlockLedgerToPeers(devPublicKey, blockLedger):
    global peers
    for peer in peers:
        obj = peer.object
        logger.debug("sending to: " + peer.peerURI)
        dat = pickle.dumps(blockLedger)
        obj.updateBlockLedger(devPublicKey, dat)

def sendIoTBlockToPeers(IoTBlock):
    global peers
    for peer in peers:
        obj = peer.object
        logger.debug("sending IoT Block to: " + peer.peerURI)
        dat = pickle.dumps(IoTBlock)
        obj.updateIOTBlockLedger(dat)

def syncChain(newPeer):
    obj = newPeer.object
    for block in IoTLedger:
        if(obj.findBlock(block.publicKey) != False):
            obj.addIoTBlock(block)


    return True

def getMyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP

#############################################################################
#########################    CRIPTOGRAPHY    ################################
#############################################################################
def generateAESKey(devPubKey):
    global genKeysPars
    randomAESKey = os.urandom(32)  # AES key: 256 bits
    obj = DeviceKeyMapping.DeviceKeyMapping(devPubKey, randomAESKey)
    genKeysPars.append(obj)
    return randomAESKey

#############################################################################
#################    Consensus Algorithm Methods    #########################
#############################################################################
def isValidBlock(newBlock, gatewayPublicKey, devicePublicKey):
    blockIoT = findBlock(devicePublicKey)
    if blockIoT == False:
        print("Block not found in IoT ledger")
        return False

    lastBlock = blockIoT.blockLedger[len(blockIoT.blockLedger) - 1]
    if newBlock.index != lastBlock.index + 1:
        print("New blovk Index not valid")
        return False

    if lastBlock.calculateHashForBlockLedger(lastBlock) != newBlock.previousHash:
        print("New block previous hash not valid")
        return False

    now = "{:.0f}".format(((time.time() * 1000) * 1000))

    # check time 
    if not (newBlock.timestamp > newBlock.signature.timestamp and newBlock.timestamp < now):
        print("New block time not valid")
        return False

    # check device time 
    if not (newBlock.signature.timestamp > lastBlock.signature.timestamp and newBlock.signature.timestamp < now):
        print("New block device time not valid")
        return False

    # check device signature with device public key 
    if not (criptoFunctions.signVerify(newBlock.signature.data, newBlock.signature.deviceSignature,
                                       gatewayPublicKey)):
        print("New block device signature not valid")
        return False

    return True

#############################################################################
######################      R2AC Class    ###################################
#############################################################################
@Pyro4.expose
@Pyro4.behavior(instance_mode="single")
class R2ac(object):
    def __init__(self):
        print("R2AC initialized")

    def info(self, devPublicKey, encryptedObj):
        global gwPvt
        global gwPub
        blk = findBlock(devPublicKey)

        if (blk != False and blk.index > 0):
            devAESKey = findAESKey(devPublicKey)
            if (devAESKey != False):
                # plainObject vira com [Assinatura + Time + Data]
                plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)

                signature = plainObject[:len(devPublicKey)]
                devTime = plainObject[len(devPublicKey):len(devPublicKey) + 16]  # 16 is the timestamp lenght
                deviceData = plainObject[len(devPublicKey) + 16:]

                deviceInfo = DeviceInfo.DeviceInfo(signature, devTime, deviceData)

                nextInt = blk.blockLedger[len(blk.blockLedger) - 1].index + 1
                signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))
                gwTime = "{:.0f}".format(((time.time() * 1000) * 1000))

                # code responsible to create the hash between Info nodes.
                prevInfoHash = criptoFunctions.calculateHashForBlockLedger(getLatestBlockLedger(blk))

                # gera um pacote do tipo Info com o deviceInfo como conteudo
                newBlockLedger = BlockLedger.BlockLedger(nextInt, prevInfoHash, gwTime, deviceInfo, signData)

                # barbara uni.. aqui!

                addBlockLedger(blk, newBlockLedger)
                logger.debug("block added locally... now sending to peers..")
                sendBlockLedgerToPeers(devPublicKey, newBlockLedger)

                return "Loucurinha!"
            return "key not found"

    def updateBlockLedger(self, pubKey, block):
        b = pickle.loads(block)
        logger.debug("Received block ledger #:" + (str(b.index)))
        blk = findBlock(pubKey)
        if blk != False:
            if not (blockContainsBlockLedger(blk, b)):
                addBlockLedger(blk, b)
        return "done"

    def updateIOTBlockLedger(self, iotBlock):
        b = pickle.loads(iotBlock)
        logger.debug("Received IoT Block ledger #:" + (str(b.index)))
        #write here the code to append the new IoT Block to the Ledger

    def auth(self, devPubKey):
        aesKey = ''
        t1 = time.time()
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

    def addPeer(self, peerURI):
        global peers
        if not (findPeer(peerURI)):
            print ("peer not found. Create new node and add to list")
            print ("adding new peer:" + peerURI)
            newPeer = PeerInfo.PeerInfo(peerURI, Pyro4.Proxy(peerURI))
            peers.append(newPeer)
            addBack(newPeer)
            syncChain(newPeer)
            return True
        return False

    def showIoTLedger(self):
        logger.debug("Showing IoT Ledger data for peer: " + myURI)
        size = len(IoTLedger)
        logger.debug("IoT Ledger size: " + str(size))
        logger.debug("---")
        for b in IoTLedger:
            logger.debug(b.strBlock())
            logger.debug("---")
        return "ok"

    def showBlockLedger(self, index):
        logger.debug("Showing Block Ledger data for peer: " + myURI)
        blk = IoTLedger[index]
        size = len(blk.blockLedger)
        logger.debug("Block Ledger size: " + str(size))
        logger.debug("-------")
        for b in blk.blockLedger:
            logger.debug(b.strBlock())
            logger.debug("-------")
        return "ok"

#############################################################################
######################          Main         ################################
#############################################################################
def main():
    global myURI
    bootstrapChain()
    print ("Please copy the server address: PYRO:chain.server...... as shown and use it in deviceSimulator.py")
    # Pyro4.config.HOST = str(getMyIP())
    daemon = Pyro4.Daemon()
    uri = daemon.register(R2ac)
    myURI = str(uri)
    print("uri=" + myURI)
    daemon.requestLoop()

if __name__ == '__main__':
    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <computer IP> <port>")
        quit()
    os.system("clear")
    main()
