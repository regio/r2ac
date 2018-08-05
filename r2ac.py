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
#import asyncio

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
#https://docs.python.org/3/library/logging.html#logrecord-attributes
FORMAT = "[%(levelname)s][%(lineno)s - %(funcName)20s()] %(message)s"
logger.basicConfig(filename=getMyIP()+str(time.time()),level=logging.DEBUG, format=FORMAT)

# Enable/Disable the  transaction validation when peer receives a transaction
validatorClient = True


app = Flask(__name__)
peers = []
genKeysPars = []
myURI = ""
gwPvt = ""
gwPub = ""


# generate the RSA key pair for the gateway
def bootstrapChain2():
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
        logger.debug("Running through peers")
        for peer in peers:
            obj = peer.object
            logger.debug("sending IoT Block to: " + str(peer.peerURI))
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


def findAESKey(devPubKey):
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


#### Consensus made by someone/....

# def consensus(newBlock, gatewayPublicKey, devicePublicKey):
#     addTrustedPeers() # just for testing, delete after
#     global peers, answers
#     threads = []
#     answers[newBlock] = []
#     #  run through peers
#     numberOfActivePeers = 0
#     for p in peers:
#         #  if trusted and active create new thread and sendBlockToConsensus
#         if peerIsTrusted(p.peerURI) and peerIsActive(p.object):
#             numberOfActivePeers = numberOfActivePeers + 1
#             t = threading.Thread(target=sendBlockToConsensus, args=(newBlock, gatewayPublicKey, devicePublicKey))
#             threads.append(t)
#     #  join threads
#     for t in threads:
#         t.join()
#
#     numberOfTrueResponses = 0
#     for a in answers[newBlock]:
#         if a: numberOfTrueResponses = numberOfTrueResponses + 1
#     #  if more then 2/3 -> true, else -> false
#     del answers[newBlock]
#     return numberOfTrueResponses >= int((2*numberOfActivePeers)/3)

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
        logger.debug("R2AC initialized")

    def addTransaction(self, devPublicKey, encryptedObj):
        logger.debug("transaction received")
        global gwPvt
        global gwPub
        t1 = time.time()
        blk = chainFunctions.findBlock(devPublicKey)

        if (blk != False and blk.index > 0):
            devAESKey = findAESKey(devPublicKey)
            if (devAESKey != False):
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
                    return "Invalid Signature"
            return "key not found"

    #update local bockchain adding a new transaction
    def updateBlockLedger(self, pubKey, block):
        b = pickle.loads(block)
        t1 = time.time()
        logger.info("Received Transaction #:" + (str(b.index)))
        blk = chainFunctions.findBlock(pubKey)
        if blk != False:
            if not (chainFunctions.blockContainsBlockTransaction(blk, b)):
                if validatorClient:
                    isTransactionValid(b, pubKey)
                chainFunctions.addBlockTransaction(blk, b)
        t2 = time.time()
        logger.info("=====3=====>time to update transaction received: " + '{0:.12f}'.format((t2 - t1) * 1000))
        return "done"

    # update local bockchain adding a new block
    def updateIOTBlockLedger(self, iotBlock):
        logger.debug("updateIoTBlockLedger Function")
        b = pickle.loads(iotBlock)
        #print("picked....")
        t1 = time.time()
        logger.debug("Received Block #:" + (str(b.index)))
        if isBlockValid(b):
            chainFunctions.addBlockHeader(b)
        t2 = time.time()
        logger.info("=====4=====>time to add new block in peers: " + '{0:.12f}'.format((t2 - t1) * 1000))

    def addBlock(self, devPubKey):
        global gwPub
        logger.debug("AddBlock Function")
        aesKey = ''
        t1 = time.time()
        blk = chainFunctions.findBlock(devPubKey)
        if (blk != False and blk.index > 0):
            aesKey = findAESKey(devPubKey)
            if aesKey == False:
                logger.info("Using existent block data")
                aesKey = generateAESKey(blk.publicKey)
        else:
            logger.info("***** New Block: Chain size:" + str(chainFunctions.getBlockchainSize()))
            bl = chainFunctions.createNewBlock(devPubKey, gwPvt)
            #sendBlockToPeers(bl)  # --->> this function should be run in a different thread.
            logger.debug("----------------------------------------")
            bbbb = criptoFunctions.calculateHashForBlock(bl)
            logger.debug("new block hash:"+str(bbbb))
            logger.debug("previous hash :"+str(bl.previousHash))
            lastBlk = chainFunctions.getLatestBlock()
            lastblockhash = criptoFunctions.calculateHashForBlock(lastBlk)
            logger.debug("last block hash:"+str(lastblockhash))
            logger.debug("----------------------------------------")
            logger.debug("starting block consensus")
            try:
                PBFTConsensus(bl, gwPub, devPubKey)
            except KeyboardInterrupt:
                sys.exit()
            except:
                print("failed to execute:")
                logger.error("failed to execute:")
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print "*** print_exception:"    
                traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=6, file=sys.stdout)
            
            logger.debug("end block consensus")
            # try:
            #     #thread.start_new_thread(sendBlockToPeers,(bl))
            #     t1 = sendBlks(1, bl)
            #     t1.start()
            # except:
            #     print "thread not working..."
            aesKey = generateAESKey(devPubKey)

        encKey = criptoFunctions.encryptRSA2(devPubKey, aesKey)
        t2 = time.time()
        logger.info("=====1=====>time to generate key: " + '{0:.12f}'.format((t2 - t1) * 1000))

        return encKey

    def addPeer(self, peerURI, isFirst):
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
        logger.info("Showing Block Header data for peer: " + myURI)
        size = chainFunctions.getBlockchainSize()
        logger.info("IoT Ledger size: " + str(size))
        logger.info("|-----------------------------------------|")
        theChain = chainFunctions.getFullChain()
        for b in theChain:
            logger.info(b.strBlock())
            logger.info("|-----------------------------------------|")
        return "ok"

    def showBlockLedger(self, index):
        logger.info("Showing Trasactions data for peer: " + myURI)
        blk = chainFunctions.getBlockByIndex(index)
        size = len(blk.transactions)
        logger.info("Block Ledger size: " + str(size))
        logger.info("-------")
        for b in blk.transactions:
            logger.info(b.strBlock())
            logger.info("-------")
        return "ok"

    def listPeer(self):
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

#####NEW CONSENSUS @Roben
    
    def verifyBlockCandidateRemote(self, newBlock):
        logger.debug("Received remote verify block candidate called...")
        global peers
        newBlock = pickle.loads(newBlock)
        logger.debug("Block received to verify:"+str(newBlock.strBlock()))
        ret = verifyBlockCandidate(newBlock, gwPub, newBlock.publicKey, peers)
        logger.debug("validation reulsts:"+str(ret))
        pi = pickle.dumps(ret)
        return pi

    #add the signature of a peer into the newBlockCandidate, using a list to all gw for a single hash, if the block is valid put the signature
    def addVoteBlockPBFTRemote(self, newBlock,voterPub,voterSign):
        logger.debug("Received remote add vote...")
        return addVoteBlockPBFT(newBlock, voterPub, voterSign)


    def calcBlockPBFTRemote(self, newBlock):
        logger.debug("Received remote calcBlock called...")
        global peers
        return calcBlockPBFT(newBlock, peers)

    def getGwPubkey(self):
        global gwPub
        return gwPub



###########
###Consensus PBFT @Roben
###########
newBlockCandidate = {} ## the idea newBlockCandidate[newBlockHash][gwPubKey] = signature, if the gateway put its signature, it is voting for YES
newTransactionCandidate = {} #same as block, for transaction

def preparePBFTConsensus(): #verify all alive peers that will particpate in consensus
    alivePeers = []
    global peers
    for p in peers:
        #if p.peerURI._pyroBind(): #verify if peer is alive
            alivePeers.append(p.peerURI)
    #return alivePeers
    return peers


######Consensus for blocks########
def PBFTConsensus(newBlock, generatorGwPub,generatorDevicePub):
    threads = []
    logger.debug("newBlock:"+str(newBlock.strBlock()))
    connectedPeers = preparePBFTConsensus() #verify who will participate in consensus
    # send the new block to the peers in order to get theirs vote.
    commitBlockPBFT(newBlock, generatorGwPub,generatorDevicePub,connectedPeers) #send to all peers and for it self the result of validation


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
    threads = []
    nbc = ""
    hashblk = criptoFunctions.calculateHashForBlock(newBlock)
    logger.debug("commiting block: "+str(hashblk))
    for p in alivePeers:
        logger.debug("Asking for confirmation from: "+str(p.peerURI))
        #verifyRet = p.object.verifyBlockCandidateRemote(pickle.dumps(newBlock), generatorGwPub, generatorDevicePub)
        picked = pickle.dumps(newBlock)
        logger.debug("ready to send...")
        verifyRet = p.object.verifyBlockCandidateRemote(picked)
        logger.debug("Answer received: "+str(verifyRet))
        if(verifyRet):
            peerPubKey = p.object.getGwPubkey()
            logger.debug("Pub Key from gateway that voted: "+str(peerPubKey))
            logger.debug("Running the add vote to block")
            addVoteBlockPBFT(newBlock, peerPubKey, verifyRet)
            calcRet = calcBlockPBFT(newBlock, alivePeers)
            logger.debug("Result from calcBlockPBFT:"+str(calcRet))
            if(calcRet):
                return

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


def verifyBlockCandidate(newBlock,generatorGwPub,generatorDevicePub,alivePeers):
    blockValidation = True
    lastBlk = chainFunctions.getLatestBlock()
    logger.debug("last block:"+str(lastBlk.strBlock()))
    lastBlkHash = criptoFunctions.calculateHashForBlock(lastBlk)
    # print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
    # lastBlkHash = criptoFunctions.calculateHash(lastBlk.index, lastBlk.previousHash, lastBlk.timestamp,
    #                                             lastBlk.publicKey)
    # print ("This Hash:"+str(lastBlkHash))
    # print ("Last Hash:"+str(block.previousHash))

    if (lastBlkHash != newBlock.previousHash):
        logger.debug("lastBlkHash="+str(lastBlkHash))
        logger.debug("newBlock-previousHash="+str(newBlock.previousHash))
        blockValidation = False
        return blockValidation
    if (int(lastBlk.index+1) != int(newBlock.index)):
        logger.debug("lastBlk Index="+str(lastBlk.index))
        logger.debug("newBlock Index="+str(newBlock.index))
        blockValidation = False
        return blockValidation
    if (lastBlk.timestamp >= newBlock.timestamp):
        logger.debug("lastBlk time:"+str(lastBlk.timestamp))
        logger.debug("lastBlk time:"+str(newBlock.timestamp))
        blockValidation = False
        return blockValidation
    if blockValidation:
        logger.debug("block successfully validated")
        voteSignature=criptoFunctions.signInfo(gwPvt, newBlock)#identify the problem in this line!!
        logger.debug("block successfully signed")
        addVoteBlockPBFT(newBlock, gwPub, voteSignature)
        logger.debug("block successfully added locally")
        return voteSignature
        #addVoteBlockPBFT(newBlock, gwPub, voteSignature) #vote positively, signing the candidate block
        # for p in alivePeers:
        #     p.object.addVoteBlockPBFTRemote(newBlock, gwPub, voteSignature) #put its vote in the list of each peer
        #return True
    else:
        logger.debug("Failed to validate")
        return False


#add the signature of a peer into the newBlockCandidate, using a list to all gw for a single hash, if the block is valid put the signature
def addVoteBlockPBFT(newBlock,voterPub,voterSign):
    global newBlockCandidate
    blockHahs = criptoFunctions.calculateHashForBlock(newTransaction)
    logger.debug("Adding the block to my local dictionary")
    if(blkHash not in newBlockCandidate):
        logger.debug("Block is not in the dictionary... creating a new one")
        newBlockCandidate[blkHash] = {}
    newBlockCandidate[blkHash][voterPub] = voterSign

    #newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)][voterPub] = voterSign
    return True

def calcBlockPBFT(newBlock,alivePeers):
    logger.debug("Running the calc blockc pbft operation")
    blHash = criptoFunctions.calculateHashForBlock(newBlock)
    logger.debug("Hash calculated")
    #if len(newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)]) > ((2/3)*len(alivePeers)):
    if (blHash in newBlockCandidate) and (len(newBlockCandidate[blHash]) > ((2/3)*len(alivePeers))):
        logger.debug("Consensus achieved!")
        chainFunctions.addBlockHeader(newBlock)
        # for p in alivePeers:
        #     p.object.insertBlock(blkHash)
        return True
    else:
        return False

######
#########################Transaction PBFT
######

##### consensus for transactions
def PBFTConsensusTransaction(block, newTransaction, generatorGwPub,generatorDevicePub):#######Consensus for transactions
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
    if (lastTransaction.index != (newTransaction.index+1)):
        transactionValidation = False
        return transactionValidation
    if (lastTransaction.timestamp >= newTransaction.timestamp):
        transactionValidation = False
        return transactionValidation
    #@Regio the publick key used below should be from device or from GW?
    if(criptoFunctions.signVerify(newTransaction.data,newTransaction.signature,generatorDevicePub)):
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
    global newTransactionCandidate
    newTransactionCandidate[criptoFunctions.calculateHashForBlock(newTransaction)][voterPub] = voterSign
    return True

def calcTransactionPBFT(block, newTransaction,alivePeers):
    if len(newTransactionCandidate[criptoFunctions.calculateHash(newTransaction)]) > ((2/3)*len(alivePeers)):
        chainFunctions.addBlockTransaction(block,newTransaction)
    return True
################################### Consensus PBFT END

#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################

def saveURItoFile(uri):
    fname = socket.gethostname()
    text_file = open(fname, "w")
    text_file.write(uri)
    text_file.close()

def main():
    global myURI
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
    daemon.requestLoop()

if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <Pyro4 Namer Server IP>")
        print (" *** remember launch in a new terminal or machine the name server: pyro4-ns -n <machine IP>  ***")
        quit()
    os.system("clear")
    main()
