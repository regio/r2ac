import pickle
import Pyro4
import socket
import logging.config
import logging as logger
import os
import sys
import time
import threading
import merkle

import thread
from os import listdir
from os.path import isfile, join
from flask import Flask, request
from Crypto.PublicKey import RSA

import Transaction
import DeviceInfo
import PeerInfo
import DeviceKeyMapping
import chainFunctions
import criptoFunctions


def getMyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP

# logging.config.fileConfig('logging.conf')
# logger = logging.getLogger(__name__)
logger.basicConfig(filename=getMyIP(),level=logging.DEBUG)

# Enable/Disable the  transaction validation when peer receives a transaction
validatorClient = True

app = Flask(__name__)
peers = []
BlockHeaderChain = []
genKeysPars = []
myURI = ""

gwPvt = ""
gwPub = ""

g = chainFunctions.getGenesisBlock()
BlockHeaderChain.append(g)


# generate the RSA key pair for the gateway
def bootstrapChain2():
    global gwPub
    global gwPvt
    gwPub, gwPvt = criptoFunctions.generateRSAKeyPair()

def createNewBlock(devPubKey):
    newBlock = chainFunctions.generateNextBlock("new block", devPubKey, getLatestBlock(), gwPvt)
    addBlockHeader(newBlock)
    return newBlock

def addBlockHeader(newBlockHeader):
    global BlockHeaderChain
    BlockHeaderChain.append(newBlockHeader)

def addBlockTransaction(IoTBlock, newBlockLedger):
    IoTBlock.transactions.append(newBlockLedger)

def getLatestBlock():
    global BlockHeaderChain
    return BlockHeaderChain[len(BlockHeaderChain) - 1]

def getLatestBlockTransaction(blk):
    return blk.transactions[len(blk.transactions) - 1]

def blockContainsBlockTransaction(block, blockLedger):
    for bl in block.transactions:
        if bl == blockLedger:
            return True
    return False

def findBlock(key):
    global BlockHeaderChain
    for b in BlockHeaderChain:
        if (b.publicKey == key):
            return b
    return False

def findAESKey(devPubKey):
    global genKeysPars
    for b in genKeysPars:
        if (b.publicKey == devPubKey):
            return b.AESKey
    return False

#############################################################################
#############################################################################
#########################    PEER MANAGEMENT  ###############################
#############################################################################
#############################################################################

def findPeer(peerURI):
    global peers
    for p in peers:
        if p.peerURI == peerURI:
            return True
    return False

def getPeer(peerURI):
    global peers
    for p in peers:
        if p.peerURI == peerURI:
            return p
    return False

def addBack(peer, isFirst):
    global myURI
    if(isFirst):
        obj = peer.object
        obj.addPeer(myURI, isFirst)
    #else:
    #    print ("done adding....")

def sendTransactionToPeers(devPublicKey, blockLedger):
    global peers
    for peer in peers:
        obj = peer.object
        #logger.debug("sending to: " + peer.peerURI)
        dat = pickle.dumps(blockLedger)
        obj.updateBlockLedger(devPublicKey, dat)

# class sendBlks(threading.Thread):
#     def __init__(self, threadID, iotBlock):
#         threading.Thread.__init__(self)
#         self.threadID = threadID
#         self.iotBlock = iotBlock
#
#     def run(self):
#         print "Starting "
#         # Get lock to synchronize threads
#         global peers
#         for peer in peers:
#             print ("runnin in a thread: ")
#             obj = peer.object
#             #logger.debug("sending IoT Block to: " + peer.peerURI)
#             dat = pickle.dumps(self.iotBlock)
#             obj.updateIOTBlockLedger(dat)

def sendBlockToPeers(IoTBlock):
        global peers
        for peer in peers:
            obj = peer.object
            #logger.debug("sending IoT Block to: " + peer.peerURI)
            dat = pickle.dumps(IoTBlock)
            obj.updateIOTBlockLedger(dat)

def syncChain(newPeer):
    #write the code to identify only a change in the iot block and insert.
    return True


#this method recieves a nameServer parameter, list all remote objects connected to it, and add these remote objetcts as peers to the current node
def connectToPeers(nameServer):
    #print ("found # results:"+str(len(nameServer.list())))
    for peerURI in nameServer.list():
        if(peerURI.startswith("PYRO:") and peerURI != myURI):
            #print ("adding new peer:"+peerURI)
            addPeer2(peerURI)
        #else:
            #print ("nothing to do")
            #print (peerURI )
    print ("finished connecting to all peers")

def addPeer2(peerURI):
            global peers
            if not (findPeer(peerURI)):
                #print ("peer not found. Create new node and add to list")
                #print ("[addPeer2]adding new peer:" + peerURI)
                newPeer = PeerInfo.PeerInfo(peerURI, Pyro4.Proxy(peerURI))
                peers.append(newPeer)
                #print("Runnin addback...")
                addBack(newPeer, True)
                #syncChain(newPeer)
                #print ("finished addback...")
                return True
            return False

#############################################################################
#############################################################################
#########################    CRIPTOGRAPHY    ################################
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
#################    Consensus Algorithm Methods    #########################
#############################################################################
#############################################################################

answers = {}
trustedPeers = []

def addTrustedPeers():
    global peers
    for p in peers:
        trustedPeers.append(p.peerURI)

def consensus(newBlock, gatewayPublicKey, devicePublicKey):
    addTrustedPeers() # just for testing, delete after
    global peers, answers
    threads = []
    answers[newBlock] = []
    #  run through peers
    numberOfActivePeers = 0
    for p in peers:
        #  if trusted and active create new thread and sendBlockToConsensus
        if peerIsTrusted(p.peerURI) and peerIsActive(p.object):
            numberOfActivePeers = numberOfActivePeers + 1
            t = threading.Thread(target=sendBlockToConsensus, args=(newBlock, gatewayPublicKey, devicePublicKey))
            threads.append(t)
    #  join threads
    for t in threads:
        t.join()

    numberOfTrueResponses = 0
    for a in answers[newBlock]:
        if a: numberOfTrueResponses = numberOfTrueResponses + 1
    #  if more then 2/3 -> true, else -> false
    del answers[newBlock]
    return numberOfTrueResponses >= int((2*numberOfActivePeers)/3)

def peerIsTrusted(i):
    global trustedPeers
    for p in trustedPeers:
        if p == i: return True
    return False

def peerIsActive(i):
    return True # TO DO

def sendBlockToConsensus(newBlock, gatewayPublicKey, devicePublicKey):
    obj = peer.object
    data = pickle.dumps(newBlock)
    obj.isValidBlock(data, gatewayPublicKey, devicePublicKey)

def receiveBlockConsensus(self, data, gatewayPublicKey, devicePublicKey, consensus):
    newBlock = pickle.loads(data)
    answer[newBlock].append(consensus)

def isValidBlock(self, data, gatewayPublicKey, devicePublicKey, peer):
    newBlock = pickle.loads(data)
    blockIoT = findBlock(devicePublicKey)
    consensus = True
    if blockIoT == False:
        print("Block not found in IoT ledger")
        consensus = False

    lastBlock = blockIoT.blockLedger[len(blockIoT.blockLedger) - 1]
    if newBlock.index != lastBlock.index + 1:
        print("New blovk Index not valid")
        consensus = False

    if lastBlock.calculateHashForBlockLedger(lastBlock) != newBlock.previousHash:
        print("New block previous hash not valid")
        consensus = False

    now = "{:.0f}".format(((time.time() * 1000) * 1000))

    # check time
    if not (newBlock.timestamp > newBlock.signature.timestamp and newBlock.timestamp < now):
        print("New block time not valid")
        consensus = False

    # check device time
    if not (newBlock.signature.timestamp > lastBlock.signature.timestamp and newBlock.signature.timestamp < now):
        print("New block device time not valid")
        consensus = False

    # check device signature with device public key
    if not (criptoFunctions.signVerify(newBlock.signature.data, newBlock.signature.deviceSignature, gatewayPublicKey)):
        print("New block device signature not valid")
        consensus = False
    peer = getPeer(peer)
    obj = peer.object
    obj.receiveBlockConsensus(data, gatewayPublicKey, devicePublicKey, consensus)

def isTransactionValid(transaction,pubKey):
    data = str(transaction.data)[-22:-2]
    signature = str(transaction.data)[:-22]
    res = criptoFunctions.signVerify(data, signature, pubKey)
    return res


def isBlockValid(block):
    #Todo Fix the comparison between the hashes... for now is just a mater to simulate the time spend calculating the hashes...
    global BlockHeaderChain
    #print(str(len(BlockHeaderChain)))
    lastBlk = getLatestBlock()
    #print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
    lastBlkHash = criptoFunctions.calculateHash(lastBlk.index, lastBlk.previousHash, lastBlk.timestamp, lastBlk.publicKey)
    #print ("This Hash:"+str(lastBlkHash))
    #print ("Last Hash:"+str(block.previousHash))
    if(lastBlkHash == block.previousHash):
        return True
    else:
        return True

#############################################################################
#############################################################################
######################      R2AC Class    ###################################
#############################################################################
#############################################################################

@Pyro4.expose
@Pyro4.behavior(instance_mode="single")
class R2ac(object):
    def __init__(self):
        print("R2AC initialized")

    def addTransaction(self, devPublicKey, encryptedObj):
        global gwPvt
        global gwPub
        #print("package received")
        t1 = time.time()
        blk = findBlock(devPublicKey)

        if (blk != False and blk.index > 0):
            devAESKey = findAESKey(devPublicKey)
            if (devAESKey != False):
                # plainObject vira com [Assinatura + Time + Data]

                plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)
                signature = plainObject[:-20] # remove the last 20 chars 
                devTime = plainObject[-20:-4] # remove the 16 char of timestamp
                deviceData = plainObject[-4:] # retrieve the las 4 chars which are the data

                #Before proceeding neet to run:
                # checkDeviceSignature(signature, devPubKey)

                deviceInfo = DeviceInfo.DeviceInfo(signature, devTime, deviceData)
                nextInt = blk.transactions[len(blk.transactions) - 1].index + 1
                signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))
                gwTime = "{:.0f}".format(((time.time() * 1000) * 1000))
                # code responsible to create the hash between Info nodes.
                prevInfoHash = criptoFunctions.calculateHashForBlockLedger(getLatestBlockTransaction(blk))
                # gera um pacote do tipo Info com o deviceInfo como conteudo
                newBlockLedger = Transaction.Transaction(nextInt, prevInfoHash, gwTime, deviceInfo, signData)
                # barbara uni.. aqui!
                # send to consensus
                #if not consensus(newBlockLedger, gwPub, devPublicKey):
                #    return "Not Approved"

                addBlockTransaction(blk, newBlockLedger)
                logger.debug("block added locally... now sending to peers..")
                t2 = time.time()
                logger.debug("=====2=====>time to add transaction in a block: " + '{0:.12f}'.format((t2 - t1) * 1000))
                sendTransactionToPeers(devPublicKey, newBlockLedger) # --->> this function should be run in a different thread.
                #print("all done")
                return "ok!"
            return "key not found"

    #update local bockchain adding a new transaction
    def updateBlockLedger(self, pubKey, block):
        b = pickle.loads(block)
        t1 = time.time()
        logger.debug("Received Transaction #:" + (str(b.index)))
        blk = findBlock(pubKey)
        if blk != False:
            if not (blockContainsBlockTransaction(blk, b)):
                if(validatorClient):
                    isTransactionValid(b, pubKey)
                addBlockTransaction(blk, b)
        t2 = time.time()
        logger.debug("=====3=====>time to update transaction received: " + '{0:.12f}'.format((t2 - t1) * 1000))
        return "done"

    # update local bockchain adding a new block
    def updateIOTBlockLedger(self, iotBlock):
        b = pickle.loads(iotBlock)
        t1 = time.time()
        #logger.debug("Received Block #:" + (str(b.index)))
        if(isBlockValid(b)):
            addBlockHeader(b)
        t2 = time.time()
        logger.debug("=====4=====>time to add new block in peers: " + '{0:.12f}'.format((t2 - t1) * 1000))
        #write here the code to append the new IoT Block to the Ledger

    def addBlock(self, devPubKey):
        aesKey = ''
        t1 = time.time()
        #print(devPubKey)
        blk = findBlock(devPubKey)
        if (blk != False and blk.index > 0):
            aesKey = findAESKey(devPubKey)
            if (aesKey == False):
                logger.debug("Using existent block data")
                aesKey = generateAESKey(blk.publicKey)
        else:
            #logger.debug("Create New Block Header")
            logger.debug("***** New Block: Chain size:" + str(len(BlockHeaderChain)))
            bl = createNewBlock(devPubKey)
            sendBlockToPeers(bl)  # --->> this function should be run in a different thread.
            # try:
            #     #thread.start_new_thread(sendBlockToPeers,(bl))
            #     t1 = sendBlks(1, bl)
            #     t1.start()
            # except:
            #     print "thread not working..."
            aesKey = generateAESKey(devPubKey)
            #print("The device IoT Block Ledger is not present.")
            #print("We should write the code to create a new block here...")

        print("AES Key generated size: "+str(len(aesKey)))
        print(aesKey)
        encKey = criptoFunctions.encryptRSA2(devPubKey, aesKey)
        t2 = time.time()
        logger.debug("=====1=====>time to generate key: " + '{0:.12f}'.format((t2 - t1) * 1000))
        #logger.debug("Encrypted key:" + encKey)

        return encKey

    def addPeer(self, peerURI, isFirst):
        global peers
        #print("recived call to add peer: "+peerURI)
        if not (findPeer(peerURI)):
            #print ("peer not found. Create new node and add to list")
            #print ("[addPeer]adding new peer:" + peerURI)
            newPeer = PeerInfo.PeerInfo(peerURI, Pyro4.Proxy(peerURI))
            peers.append(newPeer)
            if(isFirst):
                #after adding the original peer, send false to avoid loop
                addBack(newPeer, False)
            syncChain(newPeer)
            return True
        else:
            print("peer is already on the list")
            return False

    def showIoTLedger(self):
        logger.debug("Showing Block Header data for peer: " + myURI)
        size = len(BlockHeaderChain)
        logger.debug("IoT Ledger size: " + str(size))
        logger.debug("|-----------------------------------------|")
        for b in BlockHeaderChain:
            logger.debug(b.strBlock())
            logger.debug("|-----------------------------------------|")
        return "ok"

    def showBlockLedger(self, index):
        logger.debug("Showing Trasactions data for peer: " + myURI)
        blk = BlockHeaderChain[index]
        size = len(blk.transactions)
        logger.debug("Block Ledger size: " + str(size))
        logger.debug("-------")
        for b in blk.transactions:
            logger.debug(b.strBlock())
            logger.debug("-------")
        return "ok"

    def listPeer(self):
        global peers
        logger.debug("|--------------------------------------|")
        for p in peers:
            logger.debug("PEER URI: "+p.peerURI)
        logger.debug("|--------------------------------------|")
        return "ok"

    def calcMerkleTree(self, blockToCalculate):
        print ("received: "+str(blockToCalculate))
        t1 = time.time()
        blk = BlockHeaderChain[blockToCalculate]
        trans = blk.transactions
        size = len(blk.transactions)
        mt = merkle.MerkleTools()
        mt.add_leaf(trans, True)
        mt.make_tree()
        t2 = time.time()
        logger.debug("=====5=====>time to generate Merkle Tree size (" + str(size) + ") : " + '{0:.12f}'.format((t2 - t1) * 1000))
        print("=====5=====>time to generate Merkle Tree size (" + str(size) + ") : " + '{0:.12f}'.format((t2 - t1) * 1000))
        return "ok"


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################

def main():
    global myURI
    bootstrapChain2()
    print ("Please copy the server address: PYRO:chain.server...... as shown and use it in deviceSimulator.py")

    names = sys.argv[1]
    ns = Pyro4.locateNS(names)
    daemon = Pyro4.Daemon(getMyIP())
    uri = daemon.register(R2ac)
    myURI = str(uri)
    ns.register(myURI, uri, True)
    print("uri=" + myURI)
    connectToPeers(ns)
    daemon.requestLoop()

if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <Pyro4 Namer Server IP>")
        print (" *** remember launch in a new terminal or machine the name server: pyro4-ns -n <machine IP>  ***")
        quit()
    os.system("clear")
    main()
