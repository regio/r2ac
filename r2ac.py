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
import traceback
import thread
import random

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
    """ Return the IP from the gateway
    @return str 
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP

def getTime():
    """ Return the IP from the gateway
    @return str
    """
    return time.time()

lock=thread.allocate_lock()
consensusLock=thread.allocate_lock()
blockConsesusCandiateList = []


# logging.config.fileConfig('logging.conf')
# logger = logging.getLogger(__name__)
#https://docs.python.org/3/library/logging.html#logrecord-attributes
FORMAT = "[%(levelname)s-%(lineno)s-%(funcName)17s()] %(message)s"
#logger.basicConfig(filename=getMyIP()+str(time.time()),level=logging.DEBUG, format=FORMAT)
logger.basicConfig(filename=getMyIP()+str(getTime()),level=logging.INFO, format=FORMAT)

# Enable/Disable the  transaction validation when peer receives a transaction
validatorClient = True

myName=socket.gethostname()

app = Flask(__name__)
peers = []
genKeysPars = []
myURI = ""
gwPvt = ""
gwPub = ""
myOwnBlock = ""
orchestratorObject=""
consensus = "PBFT" #it can be dBFT, PBFT, PoW, Witness3
votesForNewOrchestrator = [] #list of votes for new orchestrator votes are: voter gwPub, voted gwPub, signature
myVoteForNewOrchestrator =[] # my gwPub, voted gwPub, my signed vote


def bootstrapChain2():
    """ generate the RSA key pair for the gateway and create the chain"""
    global gwPub
    global gwPvt
    chainFunctions.startBlockChain()
    gwPub, gwPvt = criptoFunctions.generateRSAKeyPair()

#############################################################################
#############################################################################
#########################    PEER MANAGEMENT  ###############################
#############################################################################
#############################################################################

def findPeer(peerURI):
    """ Receive the peer URI generated automatically by pyro4 and verify if it on the network\n
        @param peerURI URI from the peer wanted\n
        @return True - peer found\n
        @return False - peer not found
    """
    global peers
    for p in peers:
        if p.peerURI == peerURI:
            return True
    return False

def getPeer(peerURI):
    """ Receive the peer URI generated automatically by pyro4 and return the peer object\n 
        @param peerURI URI from the peer wanted\n
        @return p - peer object \n
        @return False - peer not found
    """
    global peers
    for p in peers:
        if p.peerURI == peerURI:
            return p
    return False


def addBack(peer, isFirst):
    """ Receive a peer object add it to a list of peers.\n
        the var isFirst is used to ensure that the peer will only be added once.\n
        @param peer - peer object\n
        @param isFirst - Boolean condition to add only one time a peer
    """
    global myURI
    if(isFirst):
        obj = peer.object
        obj.addPeer(myURI, isFirst)
        # pickedUri = pickle.dumps(myURI)
        # print("Before gettin last chain blocks")
        # print("Picked URI in addback: " + str(pickedUri))
        # obj.getLastChainBlocks(pickedUri, 0)
    #else:
    #    print ("done adding....")

def sendTransactionToPeers(devPublicKey, transaction):
    """ Send a transaction received to all peers connected.\n
        @param devPublickey - public key from the sending device\n
        @param transaction - info to be add to a block
    """
    global peers
    for peer in peers:
        obj = peer.object
        #logger.debug("sending to: " + peer.peerURI)
        trans = pickle.dumps(transaction)
        obj.updateBlockLedger(devPublicKey, trans)

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
    """  
    Receive a block and send it to all peers connected.\n
    @param IoTBlock - BlockHeader object
    """
    global peers
    print("sending block to peers")
    logger.debug("Running through peers")
    for peer in peers:
        #print ("Inside for in peers")
        obj = peer.object
        print("sending IoT Block to: " + str(peer.peerURI))
        logger.debug("sending IoT Block to: " + str(peer.peerURI))
        dat = pickle.dumps(IoTBlock)
        obj.updateIOTBlockLedger(dat,myName)
    print("block sent to all peers")

def syncChain(newPeer):
    """
    Send the actual chain to a new peer\n
    @param newPeer - peer object

    TODO update this pydoc after write this method code
    """
    #write the code to identify only a change in the iot block and insert.
    return True



def connectToPeers(nameServer):
    """this method recieves a nameServer parameter, list all remote objects connected to it, and 
    add these remote objetcts as peers to the current node \n
    @param nameServer - list all remote objects connected to it
    """
    #print ("found # results:"+str(len(nameServer.list())))
    for peerURI in nameServer.list():
        if(peerURI.startswith("PYRO:") and peerURI != myURI):
            #print ("adding new peer:"+peerURI)
            addPeer2(peerURI)
            #orchestratorObject.
        #else:
            #print ("nothing to do")
            #print (peerURI )
    print ("finished connecting to all peers")

def addPeer2(peerURI):
    """ Receive a peerURI and add the peer to the network if it is not already in\n
        @param peerURI - peer id on the network\n
        @return True - peer added to the network\n
        @return False - peer already in the network
    """
    global peers
    if not (findPeer(peerURI)):
        print ("peer not found. Create new node and add to list")
        print ("[addPeer2]adding new peer:" + peerURI)
        newPeer = PeerInfo.PeerInfo(peerURI, Pyro4.Proxy(peerURI))
        peers.append(newPeer)
        print("Runnin addback...")
        addBack(newPeer, True)
        #syncChain(newPeer)
        print ("finished addback...")
        return True
    return False

#############################################################################
#############################################################################
#########################    CRIPTOGRAPHY    ################################
#############################################################################
#############################################################################

def generateAESKey(devPubKey):
    """ Receive a public key and generate a private key to it with AES 256\n
        @param devPubKey - device public key\n
        @return randomAESKey - private key linked to the device public key
    """
    global genKeysPars
    randomAESKey = os.urandom(32)  # AES key: 256 bits
    obj = DeviceKeyMapping.DeviceKeyMapping(devPubKey, randomAESKey)
    genKeysPars.append(obj)
    return randomAESKey


def findAESKey(devPubKey):
    """ Receive the public key from a device and found the private key linked to it\n
        @param devPubKey - device public key\n
        @return AESkey - found the key\n
        @return False - public key not found
    """
    global genKeysPars
    for b in genKeysPars:
        if (b.publicKey == devPubKey):
            return b.AESKey
    return False


#############################################################################
#############################################################################
#################    Consensus Algorithm Methods    #########################
#############################################################################
#############################################################################

answers = {}
trustedPeers = []


def addTrustedPeers():
    """ Run on the peers list and add all to a list called trustedPeers """
    global peers
    for p in peers:
        trustedPeers.append(p.peerURI)



############################ Consensus PoW
####TODO -> should create a nonce in the block and in the transaction in order to generate it
#### we could add also a signature set (at least 5 as ethereum or 8 as bitcoin?) to do before send the block for update
#### peers should verify both block data, hash, timestamp, etc and the signatures, very similar to what is done by verifyBlockCandidate
#### maybe this verifications could be put in a another method... maybe something called " verifyBlockData "
 ###########################END NEW CONSENSUS @Roben
 ##########################

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
    blockIoT = chainFunctions.findBlock(devicePublicKey)
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
    #global BlockHeaderChain
    #print(str(len(BlockHeaderChain)))
    lastBlk = chainFunctions.getLatestBlock()
    #print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
    #lastBlkHash = criptoFunctions.calculateHash(lastBlk)

    lastBlkHash = criptoFunctions.calculateHash(lastBlk.index, lastBlk.previousHash, lastBlk.timestamp, lastBlk.publicKey, lastBlk.nonce)

    #print ("This Hash:"+str(lastBlkHash))
    #print ("Last Hash:"+str(block.previousHash))
    if(lastBlkHash == block.previousHash):
        logger.info("isBlockValid == true")
        return True
    else:
        logger.error("isBlockValid == false")
        logger.error("lastBlkHash="+str(lastBlkHash))
        logger.error("block.previous="+str(block.previousHash))
        logger.error("lastBlk Index="+str(lastBlk.index))
        logger.error("block.index="+str(block.index))
        #return False
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
        """ Init the R2AC chain on the peer"""
        print("R2AC initialized")
        logger.debug("R2AC initialized")

    def addTransaction(self, devPublicKey, encryptedObj):
        """ Receive a new transaction to be add to the chain, add the transaction 
            to a block and send it to all peers\n
            @param devPublicKey - Public key from the sender device\n
            @param encryptedObj - Info of the transaction encrypted with AES 256\n
            @return "ok!" - all done\n
            @return "Invalid Signature" - an invalid key are found\n
            @return "Key not found" - the device's key are not found
        """
        logger.debug("transaction received")
        global gwPvt
        global gwPub
        t1 = time.time()
        blk = chainFunctions.findBlock(devPublicKey)
        if (blk != False and blk.index > 0):
            devAESKey = findAESKey(devPublicKey)
            if (devAESKey != False):
                logger.debug("Transaction is going to be appended to block#("+str(blk.index)+")")
                # plainObject contains [Signature + Time + Data]

                plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)
                signature = plainObject[:-20] # remove the last 20 chars 
                devTime = plainObject[-20:-4] # remove the 16 char of timestamp
                deviceData = plainObject[-4:] # retrieve the las 4 chars which are the data

                d = devTime+deviceData
                isSigned = criptoFunctions.signVerify(d, signature, devPublicKey)

                if isSigned:
                    deviceInfo = DeviceInfo.DeviceInfo(signature, devTime, deviceData)
                    nextInt = blk.transactions[len(blk.transactions) - 1].index + 1
                    signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))
                    gwTime = "{:.0f}".format(((time.time() * 1000) * 1000))
                    # code responsible to create the hash between Info nodes.
                    prevInfoHash = criptoFunctions.calculateTransactionHash(chainFunctions.getLatestBlockTransaction(blk))

                    transaction = Transaction.Transaction(nextInt, prevInfoHash, gwTime, deviceInfo, signData)

                    # send to consensus
                    #if not consensus(newBlockLedger, gwPub, devPublicKey):
                    #    return "Not Approved"
                    # if not PBFTConsensus(blk, gwPub, devPublicKey):
                    #     return "Consensus Not Reached"

                    chainFunctions.addBlockTransaction(blk, transaction)
                    logger.info("block added locally... now sending to peers..")
                    t2 = time.time()
                    logger.info("=====2=====>time to add transaction in a block: " + '{0:.12f}'.format((t2 - t1) * 1000))
                    sendTransactionToPeers(devPublicKey, transaction) # --->> this function should be run in a different thread.
                    #print("all done")
                    return "ok!"
                else:
                    logger.debug("--Transaction not appended--Transaction Invalid Signature")
                    return "Invalid Signature"
            logger.debug("--Transaction not appended--Key not found")
            return "key not found"

    def addTransactionSC(self, devPublicKey, encryptedObj):
        """ Receive a new transaction to be add to the chain, add the transaction
            to a block and send it to all peers\n
            @param devPublicKey - Public key from the sender device\n
            @param encryptedObj - Info of the transaction encrypted with AES 256\n
            @return "ok!" - all done\n
            @return "Invalid Signature" - an invalid key are found\n
            @return "Key not found" - the device's key are not found
        """
        logger.debug("transaction received")
        global gwPvt
        global gwPub
        t1 = time.time()
        blk = chainFunctions.findBlock(devPublicKey)
        if (blk != False and blk.index > 0):
            devAESKey = findAESKey(devPublicKey)
            if (devAESKey != False):
                logger.debug("Transaction is going to be appended to block#("+str(blk.index)+")")
                # plainObject contains [Signature + Time + Data]

                plainObject = criptoFunctions.decryptAES(encryptedObj, devAESKey)
                signature = plainObject[:-20] # remove the last 20 chars
                deviceData = plainObject[-36:] # retrieve the las 4 chars which are the data
                print("###Device Data: "+deviceData)
                devTime = plainObject[-20:len(deviceData)] # remove the 16 char of timestamp
                print("###devTime: "+devTime)

                d = devTime+deviceData
                isSigned = criptoFunctions.signVerify(d, signature, devPublicKey)

                if isSigned:
                    print("it is signed!!!")
                    deviceInfo = DeviceInfo.DeviceInfo(signature, devTime, deviceData)
                    nextInt = blk.transactions[len(blk.transactions) - 1].index + 1
                    signData = criptoFunctions.signInfo(gwPvt, str(deviceInfo))
                    gwTime = "{:.0f}".format(((time.time() * 1000) * 1000))
                    # code responsible to create the hash between Info nodes.
                    prevInfoHash = criptoFunctions.calculateTransactionHash(chainFunctions.getLatestBlockTransaction(blk))

                    transaction = Transaction.Transaction(nextInt, prevInfoHash, gwTime, deviceInfo, signData)

                    # send to consensus
                    #if not consensus(newBlockLedger, gwPub, devPublicKey):
                    #    return "Not Approved"
                    # if not PBFTConsensus(blk, gwPub, devPublicKey):
                    #     return "Consensus Not Reached"

                    chainFunctions.addBlockTransaction(blk, transaction)
                    logger.info("block added locally... now sending to peers..")
                    t2 = time.time()
                    logger.info("=====2=====>time to add transaction in a block: " + '{0:.12f}'.format((t2 - t1) * 1000))
                    sendTransactionToPeers(devPublicKey, transaction) # --->> this function should be run in a different thread.
                    print("all done in transations")
                    return "ok!"
                else:
                    print("Signature is not ok")
                    logger.debug("--Transaction not appended--Transaction Invalid Signature")
                    return "Invalid Signature"
            logger.debug("--Transaction not appended--Key not found")
            return "key not found"

    #update local bockchain adding a new transaction
    def updateBlockLedger(self, pubKey, transaction):
        """ Recive a new transaction and add it to the chain\n
            @param pubKey - Block public key\n
            @param transaction - Data to be insert on the block\n
            @return "done" - method done (the block are not necessarily inserted)
        """
        trans = pickle.loads(transaction)
        t1 = time.time()
        logger.info("Received Transaction #:" + (str(trans.index)))
        blk = chainFunctions.findBlock(pubKey)
        if blk != False:
            logger.info("Transaction size in the block:"+str(len(blk.transactions)))            
            if not (chainFunctions.blockContainsTransaction(blk, trans)):
                if validatorClient:
                    isTransactionValid(trans, pubKey)
                chainFunctions.addBlockTransaction(blk, trans)
        t2 = time.time()
        logger.info("=====3=====>time to update transaction received: " + '{0:.12f}'.format((t2 - t1) * 1000))
        return "done"

    # update local bockchain adding a new block
    def updateIOTBlockLedger(self, iotBlock, gwName):
        """ Receive a block and add it to the chain\n
            @param iotBlock - Block to be add\n
            @param gwName - sender peer's name
        """
        print("Updating IoT Block Ledger, in Gw: "+str(gwName))
        logger.debug("updateIoTBlockLedger Function")
        b = pickle.loads(iotBlock)
        #print("picked....")
        t1 = time.time()
        logger.debug("Received Block #:" + (str(b.index)))
        logger.info("Received block #:"+str(b.index)+" From:"+str(gwName))
        if isBlockValid(b):
            print("updating is valid...")
            chainFunctions.addBlockHeader(b)
        t2 = time.time()
        print("updating was done")
        logger.info("=====4=====>time to add new block in peers: " + '{0:.12f}'.format((t2 - t1) * 1000))


    def addBlockConsensusCandidate(self, devPubKey):
        #TODO
        global blockConsesusCandiateList
        logger.debug("================================================")
        #print("Inside addBlockConsensusCandidate, devPubKey: ")
        #print(devPubKey)
        devKey = pickle.loads(devPubKey)
        #print("Inside addBlockConsensusCandidate, devKey: ")
        #print(devPubKey)
        logger.debug("This method is executed by orchestrator."+str(devKey))
        #logger.debug("received new block consensus candidate. Queue Size:"+srt(len(blockConsesusCandiateList)))
        addNewBlockToSyncList(devKey)
        logger.debug("added to the sync list")
        logger.debug("================================================")

    def acquireLockRemote(self):
        global consensusLock
        consensusLock.acquire(1)
        return True

    def releaseLockRemote(self):
        global consensusLock
        consensusLock.release()

    def addBlock(self, devPubKey):
        """ Receive a device public key from a device and link it to A block on the chain\n
            @param devPubKey - request's device public key\n
            @return encKey - RSA encrypted key for the device be able to communicate with the peers
        """
        global gwPub
        global consensusLock

        print("addingblock... DevPubKey:" + devPubKey)
        logger.debug("|---------------------------------------------------------------------|")
        logger.debug("Block received from device")
        aesKey = ''
        t1 = time.time()
        blk = chainFunctions.findBlock(devPubKey)
        if (blk != False and blk.index > 0):
            #print("inside first if")
            aesKey = findAESKey(devPubKey)
            if aesKey == False:
                #print("inside second if")
                logger.info("Using existent block data")
                aesKey = generateAESKey(blk.publicKey)
        else:
            #print("inside else")
            logger.info("***** New Block: Chain size:" + str(chainFunctions.getBlockchainSize()))
            #####No Consensus
            # bl = chainFunctions.createNewBlock(devPubKey, gwPvt)
            # sendBlockToPeers(bl)

            ####Consensus uncoment the 3 lines
            logger.debug("starting block consensus")
            pickedKey = pickle.dumps(devPubKey)
            print("pickedKey: ")
            print(pickedKey)

            #############LockCONSENSUS STARTS HERE###############
            if(consensus=="PBFT"):
                ### PBFT elect new orchestator every time that a new block should be inserted
                self.electNewOrchestrator()
                # while(lockisNotAvailabe):
                consensusLock.acquire(1)
                for p in peers:
                    obj=p.object
                    obj.acquireLockRemote()
                #print("ConsensusLocks acquired!")
                orchestratorObject.addBlockConsensusCandidate(pickedKey)
                orchestratorObject.runPBFT()
            if(consensus=="dBFT" or consensus == "Witness3"):

                consensusLock.acquire(1) # only 1 consensus can be running at same time
                for p in peers:
                    obj=p.object
                    obj.acquireLockRemote()
                #print("ConsensusLocks acquired!")
                orchestratorObject.addBlockConsensusCandidate(pickedKey)
                orchestratorObject.rundBFT()
            if(consensus=="PoW"):
                consensusLock.acquire(1) # only 1 consensus can be running at same time
                for p in peers:
                    obj=p.object
                    obj.acquireLockRemote()
                #print("ConsensusLocks acquired!")
                self.addBlockConsensusCandidate(pickedKey)
                self.runPoW()

            #print("after orchestratorObject.addBlockConsensusCandidate")
            #try:
            #PBFTConsensus(bl, gwPub, devPubKey)
            # except KeyboardInterrupt:
            #     sys.exit()
            # except:
            #     print("failed to execute:")
            #     logger.error("failed to execute:")
            #     exc_type, exc_value, exc_traceback = sys.exc_info()
            #     print "*** print_exception:"    l
            #     traceback.print_exception(exc_type, exc_value, exc_traceback,
            #                           limit=6, file=sys.stdout)
            #
            logger.debug("end block consensus")
            # try:
            #     #thread.start_new_thread(sendBlockToPeers,(bl))
            #     t1 = sendBlks(1, bl)
            #     t1.start()
            # except:
            #     print "thread not working..."


            if(consensus=="PBFT" or consensus=="dBFT" or consensus=="Witness3" or consensus=="PoW"):
                consensusLock.release()
                for p in peers:
                    obj = p.object
                    obj.releaseLockRemote()
                #print("ConsensusLocks released!")
            ######end of lock consensus################

            aesKey = generateAESKey(devPubKey)
        #print("Before encription of rsa2")
        encKey = criptoFunctions.encryptRSA2(devPubKey, aesKey)
        t2 = time.time()
        logger.info("=====1=====>time to generate key: " + '{0:.12f}'.format((t2 - t1) * 1000))
        logger.debug("|---------------------------------------------------------------------|")
        print("block added")
        return encKey


    def addPeer(self, peerURI, isFirst):
        """ Receive a peer URI add it to a list of peers.\n
            the var isFirst is used to ensure that the peer will only be added once.\n
            @param peerURI - peer URI\n
            @param isFirst - Boolean condition to add only one time a peer\n
            @return True - peer successfully added\n
            @return False - peer is already on the list
        """
        global peers
        if not (findPeer(peerURI)):
            newPeer = PeerInfo.PeerInfo(peerURI, Pyro4.Proxy(peerURI))
            peers.append(newPeer)
            if isFirst:
                #after adding the original peer, send false to avoid loop
                addBack(newPeer, False)
            syncChain(newPeer)
            return True
        else:
            print("peer is already on the list")
            return False

    def showIoTLedger(self):
        """ Log all chain \n
            @return "ok" - done
        """
        logger.info("Showing Block Header data for peer: " + myURI)
        print("Showing Block Header data for peer: " + myURI)
        size = chainFunctions.getBlockchainSize()
        logger.info("IoT Ledger size: " + str(size))
        logger.info("|-----------------------------------------|")
        print("IoT Ledger size: " + str(size))
        print("|-----------------------------------------|")
        theChain = chainFunctions.getFullChain()
        for b in theChain:
            logger.info(b.strBlock())
            logger.info("|-----------------------------------------|")
            print(b.strBlock())
            print("|-----------------------------------------|")
        return "ok"

    def showBlockLedger(self, index):
        """ Log all transactions of a block\n
            @param index - index of the block\n
            @return "ok" - done 
        """
        print("Showing Transactions data for peer: " + myURI)
        logger.info("Showing Trasactions data for peer: " + myURI)
        blk = chainFunctions.getBlockByIndex(index)
        print("Block for index"+str(index))
        size = len(blk.transactions)
        logger.info("Block Ledger size: " + str(size))
        logger.info("-------")
        print("Block Ledger size: " + str(size))
        print("-------")
        for b in blk.transactions:
            logger.info(b.strBlock())
            logger.info("-------")
            print(b.strBlock())
            print("-------")
        return "ok"

    def listPeer(self):
        """ Log all peers in the network\n
            @return "ok" - done 
        """
        global peers
        logger.info("|--------------------------------------|")
        for p in peers:
            logger.info("PEER URI: "+p.peerURI)
        logger.info("|--------------------------------------|")
        return "ok"

    def calcMerkleTree(self, blockToCalculate):
        print ("received: "+str(blockToCalculate))
        t1 = time.time()
        blk = chainFunctions.getBlockByIndex(blockToCalculate)
        trans = blk.transactions
        size = len(blk.transactions)
        mt = merkle.MerkleTools()
        mt.add_leaf(trans, True)
        mt.make_tree()
        t2 = time.time()
        logger.info("=====5=====>time to generate Merkle Tree size (" + str(size) + ") : " + '{0:.12f}'.format((t2 - t1) * 1000))
        print("=====5=====>time to generate Merkle Tree size (" + str(size) + ") : " + '{0:.12f}'.format((t2 - t1) * 1000))
        return "ok"

    def getRemotePeerBlockChain(self):
        pickledChain = pickle.dumps(chainFunctions.getFullChain())
        return pickledChain

    #Get the missing blocks from orchestrator
    def getLastChainBlocks(self, peerURI, lastBlockIndex):
        print("Inside get last chain block...")
        chainSize=chainFunctions.getBlockchainSize()
        print("Chainsized: " + str(chainSize))
        if(chainSize > 1):
            newBlock = chainFunctions.getBlockByIndex(1)
            print("My Key is: "+ str(newBlock.publicKey) + "My index is" + str(newBlock.index))
        #destinationURI = pickle.loads(peerURI)
        #peerUri= getPeerbyPK(destinationPK)
            sendBlockToPeers(newBlock)
        # print("Inside get last chain block... requested by URI: "+destinationURI)
        # #peer=Pyro4.Proxy(destinationURI)
        # peer = PeerInfo.PeerInfo(destinationURI, Pyro4.Proxy(destinationURI))
        # obj = peer.object
        # print("After creating obj in getlastchain")
        # for index in range(lastBlockIndex+1, chainSize-1):
        #     #logger.debug("sending IoT Block to: " + str(peer.peerURI))
        #     print("Sending to peer"+ str(destinationURI) + "Block Index: "+ str(index) + "chainsize: "+ str(chainSize))
        #     newBlock=chainFunctions.getBlockByIndex(index)
        #     #dat = pickle.dumps(chainFunctions.getBlockByIndex(index))
        #     #obj.updateIOTBlockLedger(dat, myName)
        #     obj.chainFunctions.addBlockHeader(newBlock)

        print("For finished")

    def getMyOrchestrator(self):
        dat = pickle.dumps(orchestratorObject)
        return dat

    def addVoteOrchestrator(self, sentVote):
        global votesForNewOrchestrator

        dat = pickle.loads(sentVote)
        print("adding vote in remote peer"+str(dat))
        votesForNewOrchestrator.append(dat)
        print("finished adding vote for orchetrator")
        return True

    def peerVoteNewOrchestrator(self):
        global myVoteForNewOrchestrator
        global votesForNewOrchestrator
        randomGw = random.randint(0, len(peers) - 1)
        #randomGw=1
        votedURI = peers[randomGw].peerURI
        print("VotedpubKey: " + str(votedURI))
        #myVoteForNewOrchestrator = [gwPub, votedURI, criptoFunctions.signInfo(gwPvt, votedURI)]  # not safe sign, just for test
        myVoteForNewOrchestrator = votedURI
        votesForNewOrchestrator.append(myVoteForNewOrchestrator)
        pickedVote = pickle.dumps(myVoteForNewOrchestrator)
        return pickedVote

    def electNewOrchestrator(self):
        global votesForNewOrchestrator
        global orchestratorObject

        t1 = time.time()
        for peer in peers:
            obj = peer.object
            #print("objeto criado")
            receivedVote = obj.peerVoteNewOrchestrator()
            votesForNewOrchestrator.append(pickle.loads(receivedVote))
        voteNewOrchestrator()
        #newOrchestratorURI = mode(votesForNewOrchestrator)
        newOrchestratorURI = max(set(votesForNewOrchestrator), key=votesForNewOrchestrator.count)
        print("Elected node was" + newOrchestratorURI)
        orchestratorObject = Pyro4.Proxy(newOrchestratorURI)
        for peer in peers:
            obj = peer.object
            dat = pickle.dumps(orchestratorObject)
            obj.loadElectedOrchestrator(dat)
        t2 = time.time()
        logger.info("=====7=====>time to execute New Election block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
        logger.info("New Orchestator loaded is: " + str(newOrchestratorURI))
        print("New Orchestator loaded is: " + str(newOrchestratorURI))
        print("=====>time to execute New Election block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
        # orchestratorObject

    def loadElectedOrchestrator(self, data):
        global orchestratorObject

        newOrchestrator = pickle.loads(data)
        orchestratorObject = newOrchestrator
        logger.info("New Orchestator loaded is: " + str(orchestratorObject.exposedURI()))
        print("new loaded orchestrator: " + str(orchestratorObject.exposedURI()))
        return True

    def exposedURI(self):
        return myURI

    def setConsensus(self, receivedConsensus):
        global consensus
        if (receivedConsensus != consensus):
            consensus = receivedConsensus
            print("######")
            print("Changed my consensus to " + consensus)
            for p in peers:
                obj = p.object
                obj.setConsensus(receivedConsensus)
        return True

    def runPBFT(self):
        """ Run the PBFT consensus to add a new block on the chain """
        # print("I am in runPBFT")
        t1 = time.time()
        global gwPvt
        devPubKey = getBlockFromSyncList()

        blk = chainFunctions.createNewBlock(devPubKey, gwPvt, consensus)
        logger.debug("Running PBFT function to block(" + str(blk.index) + ")")

        PBFTConsensus(blk, gwPub, devPubKey)
        t2 = time.time()
        logger.info("=====6=====>time to execute block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
        print("I finished runPBFT")

    def rundBFT(self):
        """ Run the dBFT consensus to add a new block on the chain """
        # print("I am in rundBFT")
        t1 = time.time()
        global gwPvt
        devPubKey = getBlockFromSyncList()

        blk = chainFunctions.createNewBlock(devPubKey, gwPvt, consensus)
        logger.debug("Running dBFT function to block(" + str(blk.index) + ")")
        PBFTConsensus(blk, gwPub, devPubKey)
        t2 = time.time()
        logger.info("=====6=====>time to execute block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
        print("I finished rundBFT")

    ################Consensus PoW
    def runPoW(self):
        """ Run the PoW consensus to add a new block on the chain """
        print("I am in runPoW")
        t1 = time.time()
        global gwPvt
        devPubKey = getBlockFromSyncList()
        blk = chainFunctions.createNewBlock(devPubKey, gwPvt, consensus)
        print("Device PubKey (insire runPoW): " + str(devPubKey))

        if (PoWConsensus(blk, gwPub, devPubKey)):
            t2 = time.time()
            logger.info("=====6=====>time to execute PoW block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
            print("I finished runPoW")
        else:
            t2 = time.time()
            logger.info(
                "Something went wrong, time to execute PoW Block Consensus" + '{0:.12f}'.format((t2 - t1) * 1000))
            print("I finished runPoW - Wrong")

    # def voteNewOrchestratorExposed(self):
    #     global myVoteForNewOrchestrator
    #     global votesForNewOrchestrator
    #
    #     randomGw = random.randint(0, len(peers) - 1)
    #     votedpubKey = peers[randomGw].object.getGwPubkey()
    #     # print("Selected Gw is: " + str(randomGw))
    #     # print("My pubKey:"+ str(gwPub))
    #     print("VotedpubKey: " + str(votedpubKey))
    #     myVoteForNewOrchestrator = [gwPub, votedpubKey,
    #                                 criptoFunctions.signInfo(gwPvt, votedpubKey)]  # not safe sign, just for test
    #     votesForNewOrchestrator.append(myVoteForNewOrchestrator)
    #     pickedVote = pickle.dumps(myVoteForNewOrchestrator)
    #     for count in range(0, (len(peers))):
    #         # print("testing range of peers: "+ str(count))
    #         # if(peer != peers[0]):
    #         obj = peers[count].object
    #         obj.addVoteOrchestrator(pickedVote)
    #     return True
    #     # print(str(myVoteForNewOrchestrator))

#####NEW CONSENSUS @Roben
    
    def verifyBlockCandidateRemote(self, newBlock, askerPubKey):
        """ Receive a new block and verify if it's authentic\n
            @param newBlock - BlockHeader object\n
            @param askerPubKey - Public from the requesting peer\n
            @return True - the block is valid\n
            @return False - the block is not valid
        """
        global peers
        newBlock = pickle.loads(newBlock)
        logger.debug("|---------------------------------------------------------------------|")
        logger.debug("Verify for newBlock asked - index:"+str(newBlock.index))
        ret = verifyBlockCandidate(newBlock, askerPubKey, newBlock.publicKey, peers)
        logger.debug("validation reulsts:"+str(ret))
        logger.debug("|---------------------------------------------------------------------|")
        #pi = pickle.dumps(ret)
        return ret

    #
    def addVoteBlockPBFTRemote(self, newBlock,voterPub,voterSign):
        """ add the signature of a peer into the newBlockCandidate, 
            using a list to all gw for a single hash,
            if the block is valid put the signature\n

            @param newBlock - BlockHeader object\n
            @param voterPub - Public key from the voting peer\n
            @param voterSign - new block sign key\n
            @return True - addVoteBlockPFDT only return
        """
        logger.debug("Received remote add vote...")
        return addVoteBlockPBFT(newBlock, voterPub, voterSign)


    def calcBlockPBFTRemote(self, newBlock):
        """ Calculates if PBFT consensus are achived for the block\n
            @param newBlock - BlockHeader object\n
            @return boolean - True for consensus achived, False if it's not.
        """
        logger.debug("Received remote calcBlock called...")
        global peers
        return calcBlockPBFT(newBlock, peers)

    def getGwPubkey(self):
        """ Return the peer's public key\n
            @return str - public key
        """
        global gwPub
        return gwPub

    def isBlockInTheChain(self, devPubKey):
        """ Verify if a block is on the chain\n
            @param devPubKey - block pub key\n
            @return boolean - True: block found, False: block not found
        """
        blk = chainFunctions.findBlock(devPubKey)
        #print("Inside inBlockInTheChain, devPumyVoteForNewOrchestratorbKey= " + str(devPubKey))
        if(blk == False):
            logger.debug("Block is false="+str(devPubKey))
            return False
        else:
            return True





def addNewBlockToSyncList(devPubKey):
    """ Add a new block to a syncronized list through the peers\n
        @param devPubKey - Public key of the block
    """
    logger.debug("running critical stuffff......")
    #print("Inside addNewBlockToSyncLIst")
    global lock
    lock.acquire(1)
    logger.debug("running critical was acquire")
    global blockConsesusCandiateList
    logger.debug("Appending block to list :")#+srt(len(blockConsesusCandiateList)))
    #print("Inside Lock")
    blockConsesusCandiateList.append(devPubKey)
    lock.release()
    #print("Unlocked")


def getBlockFromSyncList():
    """ Get the first block at a syncronized list through the peers\n
        @return devPubKey - Public key from the block
    """
    logger.debug("running critical stuffff to get sync list......")
    global lock
    lock.acquire(1)
    logger.debug("lock aquired by get method......")
    global blockConsesusCandiateList
    if(len(blockConsesusCandiateList)>0):
        logger.debug("there is a candidade, pop it!!!")
        devPubKey = blockConsesusCandiateList.pop(0)
    lock.release()
    logger.debug("Removing block from list :")#+srt(len(blockConsesusCandiateList)))
    return devPubKey

#@Roben returning the peer that has a specified PK
def getPeerbyPK(gwPubKey):
    """ Receive the peer URI generated automatically by pyro4 and return the peer object\n
        @param publicKey publicKey from the peer wanted\n
        @return p - peer object \n
        @return False - peer not found
    """
    global peers
    for p in peers:
        obj = p.object
        print("Object GW PUB KEY: " + obj.getGwPubkey())
        if obj.getGwPubkey() == gwPubKey:
            return p.peerURI
    return False

###########
###Consensus PBFT @Roben
###########
newBlockCandidate = {} ## the idea newBlockCandidate[newBlockHash][gwPubKey] = signature, if the gateway put its signature, it is voting for YES
newTransactionCandidate = {} #same as block, for transaction

# def runPBFT():
#     """ Run the PBFT consensus to add a new block on the chain """
#     #print("I am in runPBFT")
#     t1 = time.time()
#     global gwPvt
#     devPubKey = getBlockFromSyncList()
#
#     blk = chainFunctions.createNewBlock(devPubKey, gwPvt,consensus)
#     logger.debug("Running PBFT function to block("+str(blk.index)+")")
#
#     PBFTConsensus(blk, gwPub, devPubKey)
#     t2 = time.time()
#     logger.info("=====6=====>time to execute block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
#     print("I finished runPBFT")

# def rundBFT():
#     """ Run the PBFT consensus to add a new block on the chain """
#     #print("I am in rundBFT")
#     t1 = time.time()
#     global gwPvt
#     devPubKey = getBlockFromSyncList()
#
#     blk = chainFunctions.createNewBlock(devPubKey, gwPvt,consensus)
#     logger.debug("Running PBFT function to block("+str(blk.index)+")")
#     PBFTConsensus(blk, gwPub, devPubKey)
#     t2 = time.time()
#     logger.info("=====6=====>time to execute block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
#     print("I finished rundBFT")

def preparePBFTConsensus():
    """ verify all alive peers that will particpate in consensus\n
        @return list of available peers
    """
    alivePeers = []
    global peers
    for p in peers:
        #if p.peerURI._pyroBind(): #verify if peer is alive
            alivePeers.append(p.peerURI)
    #return alivePeers
    return peers


######PBFT Consensus for blocks########
def PBFTConsensus(newBlock, generatorGwPub,generatorDevicePub):
    """ Make the configurations needed to run consensus and call the method runPBFT()\n
        @param newBlock - BlockHeader object\n
        @param generatorGwPub - Public key from the peer who want to generate the block\n
        @param generatorDevicePub - Public key from the device who want to generate the block\n
    """
    global peers
    threads = []
    logger.debug("newBlock received for PBFT Consensus")
    #connectedPeers = preparePBFTConsensus() #verify who will participate in consensus
    connectedPeers = peers
    # send the new block to the peers in order to get theirs vote.
    #commitBlockPBFT(newBlock, generatorGwPub,generatorDevicePub,connectedPeers) #send to all peers and for it self the result of validation

    #t = threading.Thread(target=commitBlockPBFT, args=(newBlock,generatorGwPub,generatorDevicePub,connectedPeers))
    #t.start()
    commitBlockPBFT(newBlock,generatorGwPub, generatorDevicePub, connectedPeers)

    # threads.append(t)
    # for t in threads:
    #     t.join()


    # if calcBlockPBFT(newBlock,connectedPeers):  # calculate, and if it is good, insert new block and call other peers to do the same
    #     for p in connectedPeers:
    #         logger.debug("calling to:"+str(p.peerURI))
    #         x = p.object.calcBlockPBFTRemote(newBlock)
    #         logger.debug("return from peer:"+str(x))
    #     #     t = threading.Thread(target=p.object.calcBlockPBFTRemote, args=(newBlock, connectedPeers))
    #     #     t.start()
    #     #     threads.append(t)
    #     # for t in threads:
    #     #     t.join()
    #     blkHash = criptoFunctions.calculateHashForBlock(newBlock)
    #     if(blkHash in newBlockCandidate):
    #         del newBlockCandidate[blkHash]
    #     #del newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)]
    #         return True
    # return False


def commitBlockPBFT(newBlock,generatorGwPub,generatorDevicePub,alivePeers):
    """ Send a new block for all the available peers on the network\n
        @param newBlock - BlockHeader object\n
        @param generatorGwPub - Public key from the peer who want to generate the block\n
        @param generatorDevicePub - Public key from the device who want to generate the block\n
    """
    threads = []
    nbc = ""
    pbftFinished = True
    i = 0
    while (pbftFinished and i<20):
        pbftAchieved = handlePBFT(newBlock, generatorGwPub, generatorGwPub, alivePeers)
        if(not pbftAchieved):
            oldId = newBlock.index
            logger.info("PBFT not achieve, Recreating block="+ str(chainFunctions.getBlockchainSize()))
            newBlock = chainFunctions.createNewBlock(generatorDevicePub, gwPvt, consensus)
            logger.info("Block Recriated ID was:("+str(oldId)+") new:("+str(newBlock.index)+")")
            i = i + 1
            print("####not pbftAchieved")
        else:
            pbftFinished = False
            print("####pbftFinished")


    #if (hashblk in newBlockCandidate) and (newBlockCandidate[hashblk] == criptoFunctions.signInfo(gwPvt, newBlock)):
        #if newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)][gwPub] == criptoFunctions.signInfo(gwPvt, newBlock):#if it was already inserted a validation for the candidade block, abort
    #    print ("block already in consensus")
    #    return
        #newBlock,generatorGwPub,generatorDevicePub,alivePeers
    # if verifyBlockCandidate(newBlock, generatorGwPub, generatorDevicePub, alivePeers):#verify if the block is valid
    #     for p in alivePeers: #call all peers to verify if block is valid
    #         t = threading.Thread(target=p.object.verifyBlockCandidateRemote, args=(pickle.dumps(newBlock),generatorGwPub,generatorDevicePub))
    #         #### @Regio -> would it be better to use "pickle.dumps(newBlock)"  instead of newBlock?
    #         threads.append(t)
    #     #  join threads
    #     for t in threads:
    #         t.join()

def handlePBFT(newBlock,generatorGwPub,generatorDevicePub,alivePeers):
    """ Send the new block to all the peers available to be verified\n
        @param newBlock - BlockHeader object\n
        @param generatorGwPub - Public key from the peer who want to generate the block\n
        @param generatorDevicePub - Public key from the device who want to generate the block\n
        @param alivePeers - list of available peers\n
        @return boolean - True: block sended to all peers, False: fail to send the block
    """
    hashblk = criptoFunctions.calculateHashForBlock(newBlock)
    logger.debug("Running commit function to block: "+str(hashblk))
    #print("######before handlePBFT first for")
    for p in alivePeers:
        logger.debug("Asking for block verification from: "+str(p.peerURI))
        #verifyRet = p.object.verifyBlockCandidateRemote(pickle.dumps(newBlock), generatorGwPub, generatorDevicePub)
        picked = pickle.dumps(newBlock)
        verifyRet = p.object.verifyBlockCandidateRemote(picked, generatorGwPub)
        logger.debug("Answer received: "+str(verifyRet))
        #print("######inside handlePBFT first for")
        if(verifyRet):
            peerPubKey = p.object.getGwPubkey()
            #logger.debug("Pub Key from gateway that voted: "+str(peerPubKey))
            logger.debug("Running the add vote to block")
            addVoteBlockPBFT(newBlock, peerPubKey, verifyRet)
            calcRet = calcBlockPBFT(newBlock, alivePeers)
            logger.debug("Result from calcBlockPBFT:"+str(calcRet))
            if(calcRet):
                logger.info("Consensus was achieve, updating peers and finishing operation")
                sendBlockToPeers(newBlock)
                #print("handlePBFT = true")
                return True
    logger.info("Consesus was not Achieved!!! Block("+str(newBlock.index)+") will not added")
    print("handlePBFT = false")
    return False


####@Roben dbft
# def handledBFT(newBlock,generatorGwPub,generatorDevicePub,alivePeers):
#     """ Send the new block to all the peers available to be verified\n
#         @param newBlock - BlockHeader object\n
#         @param generatorGwPub - Public key from the peer who want to generate the block\n
#         @param generatorDevicePub - Public key from the device who want to generate the block\n
#         @param alivePeers - list of available peers\n
#         @return boolean - True: block sended to all peers, False: fail to send the block
#     """
#     hashblk = criptoFunctions.calculateHashForBlock(newBlock)
#     logger.debug("Running commit function to block: "+str(hashblk))
#     #@Roben for p in aliverPeers and p is a delegate
#     for p in alivePeers:
#         logger.debug("Asking for block verification from: "+str(p.peerURI))
#         #verifyRet = p.object.verifyBlockCandidateRemote(pickle.dumps(newBlock), generatorGwPub, generatorDevicePub)
#         picked = pickle.dumps(newBlock)
#         verifyRet = p.object.verifyBlockCandidateRemote(picked, generatorGwPub)
#         logger.debug("Answer received: "+str(verifyRet))
#         if(verifyRet):
#             peerPubKey = p.object.getGwPubkey()
#             #logger.debug("Pub Key from gateway that voted: "+str(peerPubKey))
#             logger.debug("Running the add vote to block")
#             addVoteBlockPBFT(newBlock, peerPubKey, verifyRet)
#             calcRet = calcBlockPBFT(newBlock, alivePeers)
#             logger.debug("Result from calcBlockPBFT:"+str(calcRet))
#             if(calcRet):
#                 logger.info("Consensus was achieve, updating peers and finishing operation")
#                 sendBlockToPeers(newBlock)
#                 return True
#     logger.info("Consesus was not Achieved!!! Block("+str(newBlock.index)+") will not added")
#     return False


def verifyBlockCandidate(newBlock,generatorGwPub,generatorDevicePub,alivePeers):
    """ Checks whether the new block has the following characteristics: \n
        * The hash of the previous block are correct in the new block data\n
        * The new block index is equals to the previous block index plus one\n
        * The generation time of the last block is smaller than the new one \n
        If the new block have it all, sign it with the peer private key\n
        @return False - The block does not have one or more of the previous characteristics\n
        @return voteSignature - The block has been verified and approved
    """
    blockValidation = True
    lastBlk = chainFunctions.getLatestBlock()
    #logger.debug("last block:"+str(lastBlk.strBlock()))
    lastBlkHash = criptoFunctions.calculateHashForBlock(lastBlk)
    # print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
    # lastBlkHash = criptoFunctions.calculateHash(lastBlk.index, lastBlk.previousHash, lastBlk.timestamp,
    #                                             lastBlk.publicKey)
    # print ("This Hash:"+str(lastBlkHash))
    # print ("Last Hash:"+str(block.previousHash))

    if (lastBlkHash != newBlock.previousHash):
        logger.error("Failed to validate new block("+str(newBlock.index)+") HASH value")
        logger.debug("lastBlkHash="+str(lastBlkHash))
        logger.debug("newBlock-previousHash="+str(newBlock.previousHash))
        blockValidation = False
        return blockValidation
    if (int(lastBlk.index+1) != int(newBlock.index)):
        logger.error("Failed to validate new block("+str(newBlock.index)+") INDEX value")
        logger.debug("lastBlk Index="+str(lastBlk.index))
        logger.debug("newBlock Index="+str(newBlock.index))
        blockValidation = False
        return blockValidation
    if (lastBlk.timestamp >= newBlock.timestamp):
        logger.error("Failed to validate new block("+str(newBlock.index)+") TIME value")
        logger.debug("lastBlk time:"+str(lastBlk.timestamp))
        logger.debug("lastBlk time:"+str(newBlock.timestamp))
        blockValidation = False
        return blockValidation
    if blockValidation:
        logger.info("block successfully validated")
        voteSignature=criptoFunctions.signInfo(gwPvt, newBlock.__str__())#identify the problem in this line!!
        logger.debug("block successfully signed")
        #addVoteBlockPBFT(newBlock, gwPub, voteSignature)
        #logger.debug("block successfully added locally")
        return voteSignature
        #addVoteBlockPBFT(newBlock, gwPub, voteSignature) #vote positively, signing the candidate block
        # for p in alivePeers:
        #     p.object.addVoteBlockPBFTRemote(newBlock, gwPub, voteSignature) #put its vote in the list of each peer
        #return True
    else:
        logger.info("Failed to validate")
        return False


def addVoteBlockPBFT(newBlock,voterPub,voterSign):
    """ add the signature of a peer into the newBlockCandidate,
        using a list to all gw for a single hash, if the block is valid put the signature \n
        @return True -  why not ? :P   ... TODO why return
    """
    global newBlockCandidate
    blkHash = criptoFunctions.calculateHashForBlock(newBlock)
    logger.debug("Adding the block to my local dictionary")
    if(blkHash not in newBlockCandidate):
        logger.debug("Block is not in the dictionary... creating a new entry for it")
        newBlockCandidate[blkHash] = {}
    newBlockCandidate[blkHash][voterPub] = voterSign
    print("vote added")
    #newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)][voterPub] = voterSign
    return True

def calcBlockPBFT(newBlock,alivePeers):
    """ Verify if the new block achieved the consensus\n
        @param newBlock - BlockHeader object\n
        @param alivePeers - list of available peers\n
        @return boolean - True: consensus achived, False: consensus Not achieved yet
    """
    #print("Inside CalcBlockPBFT")
    print("Consensus:   "+ consensus)
    # if (consensus=="PoW"):
    #     return True
    logger.debug("Running the calc blockc pbft operation")
    blHash = criptoFunctions.calculateHashForBlock(newBlock)
    locDicCount = int(len(newBlockCandidate[blHash]))
    peerCount = int(len(alivePeers))
    logger.debug("local dictionary value:"+str(locDicCount))
    logger.debug("alivePeers: "+str(peerCount))
    #cont=0
    if(consensus == "PBFT" or consensus == "dBFT"):
        cont = int(float(0.667)*float(peerCount))
    if(consensus == "Witness3"):
        cont = 3
    print("##Value of cont:   "+str(cont))
    #if len(newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)]) > ((2/3)*len(alivePeers)):
    if (blHash in newBlockCandidate) and (locDicCount >= cont):
        logger.debug("Consensus achieved!")
        chainFunctions.addBlockHeader(newBlock)
        # for p in alivePeers:
        #     p.object.insertBlock(blkHash)
        print("calcBLockPBFT = True")
        return True
    else:
        logger.debug("Consensus Not achieved yet!")
        print("calcBLockPBFT = false")
        return False

######
#########################Transaction PBFT
######

##### consensus for transactions
def PBFTConsensusTransaction(block, newTransaction, generatorGwPub,generatorDevicePub):#######Consensus for transactions
    """ Run the PBFT consensus to add a new transaction to a block\n
        @param block - BlockHeader object where the transaction will be add\n
        @param newTransaction - the transaction who will be add\n
        @param generatorGwPub - Sender peer public key\n
        @generatorDevicePub - Device how create the transaction and wants to add it to a block\n
        @return boolean - True: Transaction approved to consensus, False: transaction not approved
    """
    threads = []
    connectedPeers = preparePBFTConsensus()
    commitTransactionPBFT(block, newTransaction, generatorGwPub, generatorDevicePub,connectedPeers)
    if calcTransactionPBFT(newTransaction,connectedPeers):  # calculate, and if it is good, insert new block and call other peers to do the same
        for p in connectedPeers:
            t = threading.Thread(target=p.object.calcBlockPBFT, args=(block, newTransaction, connectedPeers))
            threads.append(t)
        for t in threads:
             t.join()
        del newBlockCandidate[criptoFunctions.calculateHashForBlock(newTransaction)]
        return True
    return False


def commitTransactionPBFT(block, newTransaction, generatorGwPub, generatorDevicePub, alivePeers):
    """ Send a transaction to be validated by all peers\n
        @param block - BlockHeader object where the transaction will be add\n
        @param newTransaction - the transaction who will be add\n
        @param generatorGwPub - Sender peer public key\n
        @generatorDevicePub - Device how create the transaction and wants to add it to a block\n
        @param alivePeers - list of available peerszn\n
        @return boolean - True: sended to validation, False: transaction are not valid or already in consensus
    """
    #TODO similar to what was done with block, just different verifications
    threads = []
    if newTransactionCandidate[criptoFunctions.calculateHash(newTransaction)][gwPub] == criptoFunctions.signInfo(gwPvt, newTransaction):#if it was already inserted a validation for the candidade block, abort
        print ("transaction already in consensus")
        return False
    if verifyTransactionCandidate():#verify if the transaction is valid
        for p in alivePeers: #call all peers to verify if block is valid
            t = threading.Thread(target=p.object.verifyTransactionCandidate, args=(block,newTransaction,generatorGwPub,generatorDevicePub,alivePeers))
            #### @Regio -> would it be better to use "pickle.dumps(newBlock)"  instead of newBlock?
            threads.append(t)
        #  join threads
        for t in threads:
            t.join()
        return True
    return False


def verifyTransactionCandidate(block,newTransaction, generatorGwPub,generatorDevicePub,alivePeers):
    """ Checks whether the new transaction has the following characteristics:\n
        * The block is on the chain\n
        * The last transaction hash on the chain and the new transaction are the same\n
        * The index of the new transaction are the index of the last transaction plus one\n
        * The generation time of the last transaction is smaller than the new one \n
        * The data is sign by the TODO (generator device or gateway)
        @param block - BlockHeader object where the transaction will be add\n
        @param newTransaction - the transaction who will be add\n
        @param generatorGwPub - Sender peer public key\n
        @generatorDevicePub - Device how create the transaction and wants to add it to a block\n
        @param alivePeers - list of available peers\n
        @return boolean - True: approved, False: not approved
    """
    transactionValidation = True
    if (chainFunctions.getBlockByIndex(block.index))!=block:
        transactionValidation = False
        return transactionValidation

    lastTransaction = chainFunctions.getLatestBlockTransaction(block)
    # print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
    lastTransactionHash = criptoFunctions.calculateHash(lastTransaction.index, lastTransaction.previousHash, lastTransaction.timestamp,
                                                lastTransaction.data, lastTransaction.signature)
    # print ("This Hash:"+str(lastBlkHash))
    # print ("Last Hash:"+str(block.previousHash))
    if (lastTransactionHash != newTransaction.previousHash):
        transactionValidation = False
        return transactionValidation
    if (newTransaction.index != (lastTransactionHash.index+1)):
        transactionValidation = False
        return transactionValidation
    if (lastTransaction.timestamp <= newTransaction.timestamp):
        transactionValidation = False
        return transactionValidation
    #@Regio the publick key used below should be from device or from GW?
    if not (criptoFunctions.signVerify(newTransaction.data,newTransaction.signature,generatorDevicePub)):
        transactionValidation = False
        return transactionValidation
    if transactionValidation:
        voteSignature=criptoFunctions.signInfo(gwPvt, newTransaction)
        addVoteTransactionPBFT(newTransaction, gwPub, voteSignature) #vote positively, signing the candidate transaction
        for p in alivePeers:
            p.object.addVoteBlockPBFT(newTransaction, gwPub, voteSignature) #put its vote in the list of each peer
        return True
    else:
        return False


def addVoteTransactionPBFT(newTransaction,voterPub,voterSign):
    """ Add the vote of the peer to the transaction\n
        @param newTransaction - Transaction object\n
        @param voterPub - vote of the peer\n
        @param voterSing - sing of the peer\n
        @return True TODO needed?
    """
    global newTransactionCandidate
    newTransactionCandidate[criptoFunctions.calculateHashForBlock(newTransaction)][voterPub] = voterSign
    return True


def calcTransactionPBFT(block, newTransaction,alivePeers):
    """ If consensus are achivied, add the transaction to the block\n
        @param block - BlockHeader object where the transaction will be add\n
        @param newTransaction - the transaction who will be add\n
        @param alivePeers - list of available peers\n
        @return True TODO needed?
    """
    if len(newTransactionCandidate[criptoFunctions.calculateHash(newTransaction)]) > ((2/3)*len(alivePeers)):
        chainFunctions.addBlockTransaction(block,newTransaction)
    return True
################################### Consensus PBFT END


# ################Consensus PoW
# def runPoW():
#     """ Run the PoW consensus to add a new block on the chain """
#     print("I am in runPoW")
#     t1 = time.time()
#     global gwPvt
#     devPubKey = getBlockFromSyncList()
#     blk = chainFunctions.createNewBlock(devPubKey, gwPvt, consensus)
#     print("Device PubKey (insire runPoW): " + str(devPubKey))
#
#     if(PoWConsensus(blk, gwPub, devPubKey)):
#         t2 = time.time()
#         logger.info("=====6=====>time to execute PoW block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))
#         print("I finished runPoW")
#     else:
#         t2 = time.time()
#         logger.info("Something went wrong, time to execute PoW Block Consensus" + '{0:.12f}'.format((t2 - t1) * 1000))
#         print("I finished runPoW - Wrong")



def PoWConsensus(newBlock, generatorGwPub,generatorDevicePub):
    """ Make the configurations needed to run consensus and call the method runPBFT()\n
        @param newBlock - BlockHeader object\n
        @param generatorGwPub - Public key from the peer who want to generate the block\n
        @param generatorDevicePub - Public key from the device who want to generate the block\n
    """
    global peers
    logger.debug("newBlock received for PoW Consensus")
    signature=verifyBlockCandidate(newBlock, generatorGwPub, generatorDevicePub,peers)
    if (signature == False):
        logger.info("Consesus was not Achieved!!! Block(" + str(newBlock.index) + ") will not added")
        return False
    addVoteBlockPoW(newBlock, generatorGwPub, signature)
    logger.info("Consensus was achieve, updating peers and finishing operation")
    chainFunctions.addBlockHeader(newBlock)
    sendBlockToPeers(newBlock)

    return True


def addVoteBlockPoW(newBlock,voterPub,voterSign):
    """ add the signature of a peer into the newBlockCandidate,
        using a list to all gw for a single hash, if the block is valid put the signature \n
        @return True -  why not ? :P   ... TODO why return
    """
    global newBlockCandidate
    blkHash = criptoFunctions.calculateHashForBlock(newBlock)
    logger.debug("Adding the block to my local dictionary")
    if(blkHash not in newBlockCandidate):
        logger.debug("Block is not in the dictionary... creating a new entry for it")
        newBlockCandidate[blkHash] = {}
    newBlockCandidate[blkHash][voterPub] = voterSign
    print("PoW vote added")
    #newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)][voterPub] = voterSign
    return True


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################

###@Roben update to load orchestrator by block index
#get first gw pkey
def loadOrchestratorIndex(index):
    global orchestratorObject

    orchestratorGWblock = chainFunctions.getBlockByIndex(index)
    orchestratorGWpk = orchestratorGWblock.publicKey
    print("Public Key inside loadOrchestratorINdex: " + orchestratorGWpk)
    if (orchestratorGWpk == gwPub): #if I am the orchestrator, use my URI
        uri=myURI
    else:
        uri = getPeerbyPK(orchestratorGWpk)
    print("loading orchestrator URI: " + uri)
    orchestratorObject=Pyro4.Proxy(uri)
#    return orchestratorObject

def loadOrchestratorFirstinPeers():
    global orchestratorObject

    if(len(peers)<1):
        uri = myURI
        orchestratorObject = Pyro4.Proxy(uri)
        logger.info("I am my own orchestrator....")
    else:
        print("First peer is"+ peers[0].peerURI)
        #uri=peers[0].peerURI
        obj=peers[0].object
        dat=pickle.loads(obj.getMyOrchestrator())
        print("##My Orchestrator orchestrator: "+str(dat))
        logger.info("##My Orchestrator orchestrator: "+str(dat))
        orchestratorObject=dat
    #orchestratorObject = Pyro4.Proxy(uri)
    # if (orchestratorGWpk == gwPub): #if I am the orchestrator, use my URI
    #     uri=myURI
    # else:from Crypto import Random
    #     uri = getPeerbyPK(orchestratorGWpk)
    # print("loading orchestrator URI: " + uri)
    # orchestratorObject=Pyro4.Proxy(uri)

def voteNewOrchestrator():
    global myVoteForNewOrchestrator
    global votesForNewOrchestrator

    randomGw = random.randint(0, len(peers) - 1)
    votedURI = peers[randomGw].peerURI
        # print("Selected Gw is: " + str(randomGw))
        # print("My pubKey:"+ str(gwPub))
    print("votedURI: " + str(votedURI))
    #myVoteForNewOrchestrator = [gwPub, votedURI, criptoFunctions.signInfo(gwPvt, votedURI)]  # not safe sign, just for test
    myVoteForNewOrchestrator=votedURI
    votesForNewOrchestrator.append(myVoteForNewOrchestrator)
    pickedVote = pickle.dumps(myVoteForNewOrchestrator)
    for count in range(0, (len(peers))):
        # print("testing range of peers: "+ str(count))
        # if(peer != peers[0]):
        obj = peers[count].object
        obj.addVoteOrchestrator(pickedVote)
    # print(str(myVoteForNewOrchestrator))


###@Roben get the next GW PBKEYfrom Crypto import Random
# def setNextOrchestrator(consensus, newOrchestratorIndex):
#     global orchestratorObject
#     if(consensus == 'dBFT'):
#         newOrchestratorbk=chainFunctions.getBlockByIndex(newOrchestratorIndex)
#         newOrchestratorPK=newOrchestratorbk.publickey
#         uri= getPeerbyPK(newOrchestratorbk)
#         orchestratorObject=Pyro4.Proxy(uri)
#         return orchestratorObject
# ###############################################




#This method "loadOrchestrator() is deprecated... It is not used anymore...
def loadOrchestrator():
    """ Connect the peer to the orchestrator TODO automate connection with orchestrator """
    global orchestratorObject
    #text_file = open("/home/core/nodes/Gw1.txt", "r")#it will add a file to set gw1 as first orchestrator
    text_file = open("/tmp/Gw1.txt", "r")
    uri = text_file.read()
    print("I load the orchestrator, its URI is: "+uri)
    print(uri)
    logger.debug("Orchestrator address loaded")
    orchestratorObject = Pyro4.Proxy(uri)
    text_file.close()


def runMasterThread():
    """ initialize the PBFT of the peer """
    #@Roben atualizacao para definir dinamicamente quem controla a votacao - o orchestrator -
    #global currentOrchestrator
    #
    #
    #while(currentOrchestrator == myURI):
    print("Inside runMasterThread")
    while(True):
        if (orchestratorObject.exposedURI() == myURI):
            if (consensus == "PoW"):
                if(len(blockConsesusCandiateList)>0):
                    print("going to runPoW")
                    runPoW()
            if (consensus == "PBFT"):
                if(len(blockConsesusCandiateList)>0):
                    print("going to runPBFT")
                    runPBFT()
            if (consensus == "dBFT" or consensus =="Witness3"):
                if(len(blockConsesusCandiateList)>0):
                    print("going to rundBFT")
                    rundBFT()
        time.sleep(1)




def saveOrchestratorURI(uri):
    """ save the uri of the orchestrator\n
        @param uri - orchestrator URI
    """
    #text_file = open("/home/core/nodes/Gw1.txt", "w")
    text_file = open("/tmp/Gw1.txt", "w")
    text_file.write(uri)
    text_file.close()


def saveURItoFile(uri):
    """ Save the peer's URI to a file \n
        @param uri - peers URI
    """
    fname = socket.gethostname()
    text_file = open(fname, "w")
    text_file.write(uri)
    text_file.close()

def main():
    """ Main function initiate the system"""
    global myURI
    global votesForNewOrchestrator

    #create the blockchain
    bootstrapChain2()
    print ("Please copy the server address: PYRO:chain.server...... as shown and use it in deviceSimulator.py")
    names = sys.argv[1]
    ns = Pyro4.locateNS(names)
    daemon = Pyro4.Daemon(getMyIP())
    uri = daemon.register(R2ac)
    myURI = str(uri)
    logger.debug("My object address: "+myURI)
    ns.register(myURI, uri, True)
    saveURItoFile(myURI)
    print("uri=" + myURI)
    connectToPeers(ns)
    bcSize=chainFunctions.getBlockchainSize()
    #print("Blockchain size is: "+ str(bcSize))
    numberConnectedPeers = len(peers)
    #print("Number of connecter peers is: " + str(numberConnectedPeers))
    ####Consensus
    print("hostname=" + socket.gethostname())
    #if(str(socket.gethostname())=="conseg-Inspiron-5570"): #Gateway PBFT orchestrator --Gw1 before -> old way, setting specific server as default orchestrator
    if(numberConnectedPeers<1):
        logger.info("Starging the First Gateway")
        #saveOrchestratorURI(myURI)
        logger.info("Creatin thread....")
        #print("going to master thread")
        loadOrchestratorFirstinPeers()
        #firstGwBlock = chainFunctions.createNewBlock(gwPub, gwPvt, consensus
        #chainFunctions.addBlockHeader(firstGwBlock)
        #R2ac.updateIOTBlockLedger(firstGwBlock, myName)
        #loadOrchestrator()
        #loadOrchestratorIndex(1)
        #threading.Thread(target=runMasterThread).start()
    else:
        loadOrchestratorFirstinPeers()
        #time.sleep(5)
        # print("inside main else")
        # pickedUri = pickle.dumps(myURI)
        # for peer in peers:
        #     obj = peer.object
        #     print("Before gettin last chain blocks")
        #     obj.getLastChainBlocks(pickedUri, chainFunctions.getBlockchainSize())
        # # loadOrchestratorIndex(1)
        # if (len(peers)>3):
        #     electNewOrchestor()
        #loadOrchestrator()
        #threading.Thread(target=runMasterThread).start()
        #print("tamanho de todos os votos: "+str(len(votesForNewOrchestrator)))

        #print("after getting last chain blocks")
    daemon.requestLoop()

if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <Pyro4 Namer Server IP>")
        print (" *** remember launch in a new terminal or machine the name server: pyro4-ns -n <machine IP>  ***")
        quit()
    os.system("clear")
    main()