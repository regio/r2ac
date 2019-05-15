import Pyro4
import json
import os
import random
import requests
import sys
import traceback
import time
import socket
import logging.config
import logging as logger
from Crypto.PublicKey import RSA

import criptoFunctions

fname = socket.gethostname()
FORMAT = "[%(levelname)s-%(lineno)s-%(funcName)17s()] %(message)s"
logger.basicConfig(filename=str(fname)+"log",level=logging.DEBUG, format=FORMAT)


server = "localhost"
serverAESEncKey = ""
serverAESKey = ""
privateKey = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA7P6DKm54NjLE7ajy\nTks298FEJeHJNxGT+7DjbTQgJdZKjQ6X9lYW8ittiMnvds6qDL95eYFgZCvO22YT\nd1vU1QIDAQABAkBEzTajEOMRSPfmzw9ZL3jLwG3aWYwi0pWVkirUPze+A8MTp1Gj\njaGgR3sPinZ3EqtiTA+PveMQqBsCv0rKA8NZAiEA/swxaCp2TnJ4zDHyUTipvJH2\nqe+KTPBHMvOAX5zLNNcCIQDuHM/gISL2hF2FZHBBMT0kGFOCcWBW1FMbsUqtWcpi\nMwIhAM5s0a5JkHV3qkQMRvvkgydBvevpJEu28ofl3OAZYEwbAiBJHKmrfSE6Jlx8\n5+Eb8119psaFiAB3yMwX9bEjVy2wRwIgd5X3n2wD8tQXcq1T6S9nr1U1dmTz7407\n1UbKzu4J8GQ=\n-----END PRIVATE KEY-----\n"
publicKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"

import __builtin__; input = getattr(__builtin__, 'raw_input', input)

def generateRSAKeyPair():
    """ Creates a pair of RSA key, one public and one private.\n
        @return pub - public key\n
        @return prv - private key
    """
    private = RSA.generate(1024)
    pubKey = private.publickey()
    prv = private.exportKey()
    pub = pubKey.exportKey()
    return pub, prv


def setServer():
    """ Ask for the user to input the server URI and put it in the global var 'server' """
    global server
    #server = raw_input('Gateway IP:')
    uri = input("Enter the uri of the gateway: ").strip()
    server = Pyro4.Proxy(uri)


def addBlockOnChain():
    """ Take the value of 'publicKey' var, and add it to the chain as a block"""
    global serverAESEncKey
    serverAESEncKey = server.addBlock(publicKey)
    #while len(serverAESEncKey) < 10:
    #    serverAESEncKey = server.addBlock(publicKey)
    decryptAESKey(serverAESEncKey)

def sendDataTest():
    """ Send fake data to test the system """
    pub, priv = generateRSAKeyPair()
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    signedData = criptoFunctions.signInfo(priv, data)
    ver = criptoFunctions.signVerify(data, signedData, pub)
    logger.debug("Sending data teste: " + str(ver))
    print ("done: "+str(ver))


def sendData():
    """ Read the sensor data, encrypt it and send it as a transaction to be validated by the peers """
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    # print("data:"+data)
    signedData = criptoFunctions.signInfo(privateKey, data)
    toSend = signedData + timeStr + temperature
    encobj = criptoFunctions.encryptAES(toSend, serverAESKey)
    server.addTransaction(publicKey, encobj)


def decryptAESKey(data):
    """ Receive a encrypted data, decrypt it and put it in the global var 'serverAESKey' """
    global serverAESKey
    serverAESKey = criptoFunctions.decryptRSA2(privateKey, data)


def readSensorTemperature():
    """ Generates random data like '23 C' """
    temp = str(random.randint(10, 40)) + " C"
    return temp

def addPeer():
    """ Ask for the user to inform a peer URI and add it to the server """
    # if sys.version_info < (3, 0):
    #     input = raw_input
    uri = input("Enter the PEER uri: ").strip()
    server.addPeer(uri, True)

def listBlockHeader():
    """ Log all blocks """
    server.showIoTLedger()

def listTransactions():
    """ Ask for the user to input an index and show all transaction of the block with that index """
    index = input("Which IoT Block do you want to print?")
    server.showBlockLedger(index)

def listPeers():
    """ List all peers in the network """
    print("calling server...")
    server.listPeer()

def newKeyPair():
    """ Generates a new pair of keys and put is on global vars 'privateKey' and 'publicKey' """
    global privateKey
    global publicKey
    publicKey, privateKey = generateRSAKeyPair()
    while len(publicKey) < 10 or len(privateKey) < 10:
        publicKey, privateKey = generateRSAKeyPair()


def brutePairAuth(retry):
    """ Add a block on the chain with brute force until it's add"""
    isOk=True
    while isOk:
        try:
            newKeyPair()
            addBlockOnChain()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            logger.debug("failed to execute:"+str(retry))
            print("failed to execute:"+str(retry))
            isOk = True

def bruteSend(retry):
    """ Try to send a random data with brute force until it's sended """
    isOk=True
    while isOk:
        try:
            sendData()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            logger.debug("failed to execute:"+str(retry))
            print("failed to execute sendData:"+str(retry))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.debug("*** print_exception:")
            logger.debug(str(traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=2, file=sys.stdout)))
            print "*** print_exception:"
            traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=2, file=sys.stdout)
            global serverAESKey
            print("the size of the serverAESKey is: "+str(len(serverAESKey)))
            return


def defineAutomaNumbers():
    """ Ask for the user to input how many blocks and transaction he wants and calls the function automa()"""
    blocks = int(input('How many Blocks:'))
    trans = int(input('How many Transactions:'))
    automa(blocks, trans)

def automa(blocks, trans):
    """ Adds a specifc number of blocks and transaction to the chain\n
        @param blocks - int number of blocks\n
        @param trans - int number of transactions
    """
    print ("Block #:")
    logger.debug("Block #:")
    for blk in range(0, blocks):
        logger.debug(str(blk))
        print (str(blk))
        newKeyPair()
        addBlockOnChain()
        #brutePairAuth(blk)
        for tr in range(0, trans):
            #sendData()
            while (not (server.isBlockInTheChain(publicKey))):
                continue
                #time.sleep(1)
            bruteSend(tr)


def merkle():
    """ Calculates the hash markle tree of the block """
    blk = int(input("Which block you want to create the merkle tree:"))
    server.calcMerkleTree(blk)
    print ("done")

def loadConnection():
    """ Load the URI of the connection  """
    global server
    fname = socket.gethostname()
    text_file = open(fname, "r")
    uri = text_file.read()
    print(uri)
    server = Pyro4.Proxy(uri)
    text_file.close()
    #os.remove(fname)



#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def main():
    """ Creates an interactive screen for the user with all option of a device"""
    global server
    options = {
               1: setServer,
               2: addPeer,
               3: addBlockOnChain,
               4: sendData,
               5: listBlockHeader,
               6: listTransactions,
               7: listPeers,
               8: newKeyPair,
               9: defineAutomaNumbers,
               10: merkle
               }

    mode = -1
    while True:
        print("Choose your option [" + str(server) + "]")
        print("0 - Exit")
        print("1 - Set Server Address[ex:PYRO:chain.server@blablabala:00000]")
        print("2 - Add Peer")
        print("3 - Authentication Request [a)Gw Generate AES Key;b)Enc key with RSA;c)Dec AES Key]")
        print("4 - Produce Data [a)sign data;b)encrypt with AES key;c)Send to Gateway;d)GW update ledger and peers")
        print("5 - List Block Headers from connected Gateway")
        print("6 - List Transactions for a given Block Header")
        print("7 - List PEERS")
        print("8 - Recreate Device KeyPair")
        print("9 - Run a batch operation...")
        print("10 - Create Merkle Tree for a given block")
        try:
            mode = int(input('Input:'))
        except ValueError:
            print ("Not a number")
        if (mode == 0):
            break
        options[mode]()


if __name__ == '__main__':

    if len(sys.argv[1:]) > 1:
        os.system("clear")
        print("running automatically")
        loadConnection()
        bl = sys.argv[1]
        tr = sys.argv[2]
        automa(int(bl), int(tr))
    else:
        os.system("clear")
        loadConnection()
        main()
