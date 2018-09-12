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
import json

from os import listdir
from os.path import isfile, join
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA

import Transaction
import DeviceInfo
import PeerInfo
import DeviceKeyMapping
import chainFunctions
import criptoFunctions
import datetime


def getMyIP():
    """ Return the IP from the gateway
    @return str 
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP

orchestratorObject=""
lock=thread.allocate_lock()
blockConsesusCandiateList = []

# logging.config.fileConfig('logging.conf')
# logger = logging.getLogger(__name__)
#https://docs.python.org/3/library/logging.html#logrecord-attributes
FORMAT = "[%(levelname)s-%(lineno)s-%(funcName)17s()] %(message)s"
#logger.basicConfig(filename=getMyIP()+str(time.time()),level=logging.DEBUG, format=FORMAT)
logger.basicConfig(filename=getMyIP(),level=logging.INFO, format=FORMAT)

# Enable/Disable the  transaction validation when peer receives a transaction
validatorClient = True

myName=socket.gethostname()

app = Flask(__name__)
peers = []
genKeysPars = []
myURI = ""
gwPvt = ""
gwPub = ""

r2acSharedInstance = ""

def bootstrapChain2():
    """ generate the RSA key pair for the gateway and create the chain"""
    global gwPub
    global gwPvt
    chainFunctions.startBlockChain()
    gwPub, gwPvt = criptoFunctions.generateRSAKeyPair()

#############################################################################
#############################################################################
#########################    REST FAKE API  #################################
#############################################################################
#############################################################################

privateKey = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA7P6DKm54NjLE7ajy\nTks298FEJeHJNxGT+7DjbTQgJdZKjQ6X9lYW8ittiMnvds6qDL95eYFgZCvO22YT\nd1vU1QIDAQABAkBEzTajEOMRSPfmzw9ZL3jLwG3aWYwi0pWVkirUPze+A8MTp1Gj\njaGgR3sPinZ3EqtiTA+PveMQqBsCv0rKA8NZAiEA/swxaCp2TnJ4zDHyUTipvJH2\nqe+KTPBHMvOAX5zLNNcCIQDuHM/gISL2hF2FZHBBMT0kGFOCcWBW1FMbsUqtWcpi\nMwIhAM5s0a5JkHV3qkQMRvvkgydBvevpJEu28ofl3OAZYEwbAiBJHKmrfSE6Jlx8\n5+Eb8119psaFiAB3yMwX9bEjVy2wRwIgd5X3n2wD8tQXcq1T6S9nr1U1dmTz7407\n1UbKzu4J8GQ=\n-----END PRIVATE KEY-----\n"
publicKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"
serverAESEncKey = "MyCoolKey"
serverAESKey = "TheCoolestKeyaaa"

@app.route('/vote', methods=['POST'])
def addVote():
  #creates transaction data based on post body
  transactionData = json.dumps(transactionDataFromRequestValues(request.values))

  #declares temporary user public and private keys
  global privateKey
  global publicKey
  pubKey = publicKey
  priKey = privateKey

  print(r2acSharedInstance.isBlockInTheChain(pubKey))

  #if there is no block for given publick key, create a new one
  if (not r2acSharedInstance.isBlockInTheChain(pubKey)):
    r2acSharedInstance.addBlock(pubKey)
    logger.info("Finished adding block")

  t = ((time.time() * 1000) * 1000)
  timeStr = "{:.0f}".format(t)
  data = timeStr + transactionData
  signedData = criptoFunctions.signInfo(priKey, transactionData)
  toSend = signedData + timeStr + transactionData
  encobj = criptoFunctions.encryptAES(toSend, serverAESKey)
  r2acSharedInstance.addTransaction(pubKey, encobj)
  logger.info("Finished adding transaction")

  return jsonify(transactionData)

@app.route("/votesBy/<userId>")
def getAllVotesBy(userId):
  #declares temporary user public key
  pKey = publicKey
  #get block by user public key
  block = chainFunctions.findBlock(pKey)
  #get all transactions
  transactions = block.transactions
  #decripty transactions and retrieve data 
  blocksJSONED = map(lambda transaction: getJson(transaction.data.data), transactions)
  #return
  return jsonify(blocksJSONED)

@app.route("/votesTo/<newsURL>")
def getAllVotesTo(newsURL):
  #get all blocks
  chain = chainFunctions.getFullChain()
  #get all transactions
  transactions = reduce(lambda allTransactions, block: allTransactions.extend(block.transactions), chain)
  #decripty transactions
  allBlocks = map(lambda transaction: getJson(transaction.data.data), transactions)
  #filter by newsURL
  filteredBlocks = filter(lambda block: block.newsURL == newsURL, blocks)
  #return
  return jsonify(filteredBlocks)

def getJson(data):
  return {"vote": data.vote, "userId": data.userId, "newsURL": data.newsURL}

def transactionDataFromRequestValues(values):
  return {"vote": values['vote'], "userId": values['userId'], "newsURL": values['newsURL']}

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
    logger.debug("Running through peers")
    for peer in peers:
        obj = peer.object
        logger.debug("sending IoT Block to: " + str(peer.peerURI))
        dat = pickle.dumps(IoTBlock)
        obj.updateIOTBlockLedger(dat,myName)

def syncChain(newPeer):
    """
    Send the actual chain to a new peer\n
    @param newPeer - peer object

    TODO atualizar este pydoc apos escrever o metodo
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

# def peerIsTrusted(peerObj):
#     """ Run on the trustedPeers list looking for a specific peer\n
#         @param peerObj - peer object to search on the list\n
#         @return True - peer founded on the list\n
#         @return False - peer not found on the list
#     """
#     global trustedPeers
#     for p in trustedPeers:
#         if p == peerObj: return True
#     return False

# def peerIsActive(peerObj):
#     """ Receive a peer and return if it is active on the network\n
#         @param peerObj - peer wanted\n
#         @return True - The peer is active\n
#         @return False - The peer is not active
#     """
#     return True # TODO

# def sendBlockToConsensus(newBlock, gatewayPublicKey, devicePublicKey):
#     """ Send a newBlock to be validated by the the peers\n
#         @param newBlock - BlockHeader object\n
#         @param getwayPublicKey - Public key from the sending peer\n
#         @param devicePublicKey - Public key from the sending device\n
#     """
#     obj = peer.object
#     data = pickle.dumps(newBlock)
#     obj.isValidBlock(data, gatewayPublicKey, devicePublicKey)

# def receiveBlockConsensus(self, data, gatewayPublicKey, devicePublicKey, consensus):
#     """ Receive a block to be validated\n
#         @param self - class param\n
#         @param data - block data to be validated\n
#         @param getwayPubliKey - Public key from the sending peer\n
#         @param devicePublicKey - Public key from the sending device\n
#         @param consensus - actual state of consensus
    
#     """
#     newBlock = pickle.loads(data)
#     answer[newBlock].append(consensus)

# def isValidBlock(self, data, gatewayPublicKey, devicePublicKey, peer):
#     """ Receive a block and verify if it is a valid block in the chain\n
#         @param self - class param\n
#         @param data - block data\n
#         @param gatewayPublicKey - Public key from the sending peer\n
#         @param devicePublicKey - Public key from the sending device\n
#         @param peer - 
#     """
#     newBlock = pickle.loads(data)
#     blockIoT = chainFunctions.findBlock(devicePublicKey)
#     consensus = True
#     if blockIoT == False:
#         print("Block not found in IoT ledger")
#         consensus = False

#     lastBlock = blockIoT.blockLedger[len(blockIoT.blockLedger) - 1]
#     if newBlock.index != lastBlock.index + 1:
#         print("New blovk Index not valid")
#         consensus = False

#     if lastBlock.calculateHashForBlockLedger(lastBlock) != newBlock.previousHash:
#         print("New block previous hash not valid")
#         consensus = False

#     now = "{:.0f}".format(((time.time() * 1000) * 1000))

#     # check time
#     if not (newBlock.timestamp > newBlock.signature.timestamp and newBlock.timestamp < now):
#         print("New block time not valid")
#         consensus = False

#     # check device time
#     if not (newBlock.signature.timestamp > lastBlock.signature.timestamp and newBlock.signature.timestamp < now):
#         print("New block device time not valid")
#         consensus = False

#     # check device signature with device public key
#     if not (criptoFunctions.signVerify(newBlock.signature.data, newBlock.signature.deviceSignature, gatewayPublicKey)):
#         print("New block device signature not valid")
#         consensus = False
#     peer = getPeer(peer)
#     obj = peer.object
#     obj.receiveBlockConsensus(data, gatewayPublicKey, devicePublicKey, consensus)

# def isTransactionValid(transaction,pubKey):
#     data = str(transaction.data)[-22:-2]
#     signature = str(transaction.data)[:-22]
#     res = criptoFunctions.signVerify(data, signature, pubKey)
#     return res


# def isBlockValid(block):
#     #Todo Fix the comparison between the hashes... for now is just a mater to simulate the time spend calculating the hashes...
#     #global BlockHeaderChain
#     #print(str(len(BlockHeaderChain)))
#     lastBlk = chainFunctions.getLatestBlock()
#     #print("Index:"+str(lastBlk.index)+" prevHash:"+str(lastBlk.previousHash)+ " time:"+str(lastBlk.timestamp)+ " pubKey:")
#     #lastBlkHash = criptoFunctions.calculateHash(lastBlk.index, lastBlk.previousHash, lastBlk.timestamp, lastBlk.publicKey)
#     lastBlkHash = criptoFunctions.calculateHashForBlock(lastBlk)
#     #print ("This Hash:"+str(lastBlkHash))
#     #print ("Last Hash:"+str(block.previousHash))
#     if(lastBlkHash == block.previousHash):
#         logger.info("isBlockValid == true")
#         return True
#     else:
#         logger.error("isBlockValid == false")
#         logger.error("lastBlkHash="+str(lastBlkHash))
#         logger.error("block.previous="+str(block.previousHash))
#         logger.error("lastBlk Index="+str(lastBlk.index))
#         logger.error("block.index="+str(block.index))
#         return False

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
        logger.debug("updateIoTBlockLedger Function")
        b = pickle.loads(iotBlock)
        #print("picked....")
        t1 = time.time()
        logger.debug("Received Block #:" + (str(b.index)))
        logger.info("Received block #:"+str(b.index)+" From:"+str(gwName))
        if isBlockValid(b):
            chainFunctions.addBlockHeader(b)
        t2 = time.time()
        logger.info("=====4=====>time to add new block in peers: " + '{0:.12f}'.format((t2 - t1) * 1000))


    def addBlockConsensusCandidate(self, devPubKey):
        #TODO
        global blockConsesusCandiateList
        logger.debug("================================================")
        devKey = pickle.loads(devPubKey)
        logger.debug("This method is executed by orchestrator."+str(devKey))
        #logger.debug("received new block consensus candidate. Queue Size:"+srt(len(blockConsesusCandiateList)))
        addNewBlockToSyncList(devKey)
        logger.debug("added to the sync list")
        logger.debug("================================================")



    def addBlock(self, devPubKey):
        """ Receive a device public key from a device and link it to A block on the chain\n
            @param devPubKey - request's device public key\n
            @return encKey - RSA encrypted key for the device be able to communicate with the peers
        """
        global gwPub
        logger.debug("|---------------------------------------------------------------------|")
        logger.debug("Block received from device")
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
            #####No Consensus
            # bl = chainFunctions.createNewBlock(devPubKey, gwPvt)
            # sendBlockToPeers(bl)
            
            ####Consensus uncoment the 3 lines
            logger.debug("starting block consensus")
            pickedKey = pickle.dumps(devPubKey)
            orchestratorObject.addBlockConsensusCandidate(pickedKey)

            #try:
            #PBFTConsensus(bl, gwPub, devPubKey)
            # except KeyboardInterrupt:
            #     sys.exit()
            # except:
            #     print("failed to execute:")
            #     logger.error("failed to execute:")
            #     exc_type, exc_value, exc_traceback = sys.exc_info()
            #     print "*** print_exception:"    
            #     traceback.print_exception(exc_type, exc_value, exc_traceback,
            #                           limit=6, file=sys.stdout)
            
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
        logger.debug("|---------------------------------------------------------------------|")
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
        size = chainFunctions.getBlockchainSize()
        logger.info("IoT Ledger size: " + str(size))
        logger.info("|-----------------------------------------|")
        theChain = chainFunctions.getFullChain()
        for b in theChain:
            logger.info(b.strBlock())
            logger.info("|-----------------------------------------|")
        return "ok"

    def showBlockLedger(self, index):
        """ Log all transactions of a block\n
            @param index - index of the block\n
            @return "ok" - done 
        """
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
    global lock
    lock.acquire(1)
    logger.debug("running critical was acquire")
    global blockConsesusCandiateList
    logger.debug("Appending block to list :")#+srt(len(blockConsesusCandiateList)))
    blockConsesusCandiateList.append(devPubKey)
    lock.release()


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


###########
###Consensus PBFT @Roben
###########
newBlockCandidate = {} ## the idea newBlockCandidate[newBlockHash][gwPubKey] = signature, if the gateway put its signature, it is voting for YES
newTransactionCandidate = {} #same as block, for transaction

def runPBFT():
    """ Run the PBFT consensus to add a new block on the chain """
    t1 = time.time()
    global gwPvt
    devPubKey = getBlockFromSyncList()
    #TODO: randomize selection of gw to orchestrate the block creation
    blk = chainFunctions.createNewBlock(devPubKey, gwPvt)
    logger.debug("Running PBFT function to block("+str(blk.index)+")")
    PBFTConsensus(blk, gwPub, devPubKey)
    t2 = time.time()
    logger.info("=====6=====>time to execute block consensus: " + '{0:.12f}'.format((t2 - t1) * 1000))

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


######Consensus for blocks########
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
            newBlock = chainFunctions.createNewBlock(generatorDevicePub, gwPvt)
            logger.info("Block Recriated ID was:("+str(oldId)+") new:("+str(newBlock.index)+")")
            i = i + 1
        else:
            pbftFinished = False
    

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
    for p in alivePeers:
        logger.debug("Asking for block verification from: "+str(p.peerURI))
        #verifyRet = p.object.verifyBlockCandidateRemote(pickle.dumps(newBlock), generatorGwPub, generatorDevicePub)
        picked = pickle.dumps(newBlock)
        verifyRet = p.object.verifyBlockCandidateRemote(picked, generatorGwPub)
        logger.debug("Answer received: "+str(verifyRet))
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
                return True
    logger.info("Consesus was not Achieved!!! Block("+str(newBlock.index)+") will not added")
    return False


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

    #newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)][voterPub] = voterSign
    return True

def calcBlockPBFT(newBlock,alivePeers):
    """ Verify if the new block achieved the consensus\n
        @param newBlock - BlockHeader object\n
        @param alivePeers - list of available peers\n
        @return boolean - True: consensus achived, False: consensus Not achieved yet
    """
    logger.debug("Running the calc blockc pbft operation")
    blHash = criptoFunctions.calculateHashForBlock(newBlock)
    locDicCount = int(len(newBlockCandidate[blHash]))
    peerCount = int(len(alivePeers))
    logger.debug("local dictionary value:"+str(locDicCount))
    logger.debug("alivePeers: "+str(peerCount))
    #cont = int(float(0.667)*float(peerCount))
    cont = int(float(0.1)*float(peerCount))
    #if len(newBlockCandidate[criptoFunctions.calculateHashForBlock(newBlock)]) > ((2/3)*len(alivePeers)):
    if (blHash in newBlockCandidate) and (locDicCount >= cont):
        logger.debug("Consensus achieved!")
        chainFunctions.addBlockHeader(newBlock)
        # for p in alivePeers:
        #     p.object.insertBlock(blkHash)
        return True
    else:
        logger.debug("Consensus Not achieved yet!")
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

#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def loadOrchestrator():
    """ Connect the peer to the orchestrator TODO automate connection with orchestrator """
    global orchestratorObject
    text_file = open("/home/core/nodes/Gw1.txt", "r")
    uri = text_file.read()
    print(uri)
    logger.debug("Orchestrator address loaded")
    orchestratorObject = Pyro4.Proxy(uri)
    text_file.close()


def runMasterThread():
    """ initialize the PBFT of the peer """
    while(True):
        if(len(blockConsesusCandiateList)>0):
            runPBFT()
        #time.sleep(0.001)


def saveOrchestratorURI(uri):
    """ save the uri of the orchestrator\n
        @param uri - orchestrator URI
    """
    text_file = open("/home/core/nodes/Gw1.txt", "w")
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

    global r2acSharedInstance
    r2acSharedInstance = Pyro4.Proxy(str(uri))

    connectToPeers(ns)

    ####Consensus
    if(str(socket.gethostname())=="Gw1"): #Gateway PBFT orchestrator
        logger.debug("Starging the Gateway Orchestrator")
        saveOrchestratorURI(myURI)
        logger.debug("Creatin thread....")
        threading.Thread(target=runMasterThread).start()
    else:
        global orchestratorObject
        orchestratorObject = Pyro4.Proxy(str(uri))
        #loadOrchestrator()

    #runs flask
    app.run(threaded=True)
    daemon.requestLoop()

if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <Pyro4 Namer Server IP>")
        print (" *** remember launch in a new terminal or machine the name server: pyro4-ns -n <machine IP>  ***")
        quit()
    os.system("clear")
    main()
