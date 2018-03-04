import Pyro4
import json
import os
import random
import requests
import sys
import traceback
import time
from Crypto.PublicKey import RSA

import criptoFunctions

server = "localhost"
serverAESEncKey = ""
serverAESKey = ""
privateKey = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA7P6DKm54NjLE7ajy\nTks298FEJeHJNxGT+7DjbTQgJdZKjQ6X9lYW8ittiMnvds6qDL95eYFgZCvO22YT\nd1vU1QIDAQABAkBEzTajEOMRSPfmzw9ZL3jLwG3aWYwi0pWVkirUPze+A8MTp1Gj\njaGgR3sPinZ3EqtiTA+PveMQqBsCv0rKA8NZAiEA/swxaCp2TnJ4zDHyUTipvJH2\nqe+KTPBHMvOAX5zLNNcCIQDuHM/gISL2hF2FZHBBMT0kGFOCcWBW1FMbsUqtWcpi\nMwIhAM5s0a5JkHV3qkQMRvvkgydBvevpJEu28ofl3OAZYEwbAiBJHKmrfSE6Jlx8\n5+Eb8119psaFiAB3yMwX9bEjVy2wRwIgd5X3n2wD8tQXcq1T6S9nr1U1dmTz7407\n1UbKzu4J8GQ=\n-----END PRIVATE KEY-----\n"
publicKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"

def generateRSAKeyPair():
    private = RSA.generate(1024)
    pubKey = private.publickey()
    prv = private.exportKey()
    pub = pubKey.exportKey()
    return pub, prv


def setServer():
    global server
    if sys.version_info < (3, 0):
        input = raw_input
    #server = raw_input('Gateway IP:')
    uri = input("Enter the uri of the gateway: ").strip()
    server = Pyro4.Proxy(uri)


def authReq():
    global serverAESEncKey
    serverAESEncKey = server.auth(publicKey)
    while len(serverAESEncKey) < 10:
        serverAESEncKey = server.auth(publicKey)
    # headers = {'Content-type': 'application/json'}
    # payload = {'publicKey': publicKey}
    # r = requests.post("http://" + server + ":3001/auth", data=json.dumps(payload), headers=headers)
    # serverAESEncKey = r.text
    #print("AES key encrypted received from server")
    decryptAESKey(serverAESEncKey)

def sendDataTest():
    pub, priv = generateRSAKeyPair()
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    signedData = criptoFunctions.signInfo(priv, data)
    ver = criptoFunctions.signVerify(data, signedData, pub)
    print ("done: "+str(ver))


def sendData():
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    signedData = criptoFunctions.signInfo(privateKey, data)
    toSend = signedData + timeStr + temperature
    #print ("keySize:"+str(len(serverAESKey)))
    encobj = criptoFunctions.encryptAES(toSend, serverAESKey)

    #print("package ready to send...")
    server.info(publicKey, encobj)

    # headers = {'Content-type': 'application/json'}
    # payload = {'publicKey': publicKey, 'EncObj': encobj}
    # r = requests.post("http://" + server + ":3001/info", data=json.dumps(payload), headers=headers)
    # asdf = r.text
    #print("maybe worked " + asdf)


def decryptAESKey(data):
    global serverAESKey
    serverAESKey = criptoFunctions.decryptRSA2(privateKey, data)
    if(len(serverAESEncKey)<32):
        serverAESKey = criptoFunctions.decryptRSA2(privateKey, data)


def readSensorTemperature():
    temp = str(random.randint(10, 40)) + " C"
    #print("The device has read the temperature:" + temp)
    return temp

def addPeer():
    if sys.version_info < (3, 0):
        input = raw_input
    uri = input("Enter the PEER uri: ").strip()
    server.addPeer(uri, True)

def listIoTLedger():
    server.showIoTLedger()

def listBlockLedger():
    index = input("Which IoT Block do you want to print?")
    server.showBlockLedger(index)

def listPeers():
    print("calling server...")
    server.listPeer()

def newKeyPair():
    global privateKey
    global publicKey
    publicKey, privateKey = generateRSAKeyPair()
    while len(publicKey) < 10 or len(privateKey) < 10:
        publicKey, privateKey = generateRSAKeyPair()


def brutePairAuth(retry):
    isOk=True
    while isOk:
        try:
            newKeyPair()
            authReq()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            print("failed to execute:"+str(retry))
            isOk = True

def bruteSend(retry):
    isOk=True
    while isOk:
        try:
            sendData()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            print("failed to execute sendData:"+str(retry))
            # exc_type, exc_value, exc_traceback = sys.exc_info()
            # print "*** print_exception:"
            # traceback.print_exception(exc_type, exc_value, exc_traceback,
            #                           limit=2, file=sys.stdout)
            global serverAESKey
            print("the size of the serverAESKey is: "+str(len(serverAESKey)))
            return


def automa():
    blocks = int(raw_input('How many Blocks:'))
    trans = int(raw_input('How many Transactions:'))

    print "Block #:"
    for blk in range(0, blocks):
        print str(blk)
        newKeyPair()
        authReq()
        #brutePairAuth(blk)
        for tr in range(0, trans):
            #sendData()
            bruteSend(tr)


def merkle():
    blk = int(raw_input("Which block you want to create the merkle tree:"))
    server.calcMerkleTree(blk)
    print ("done")


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def main():
    global server
    options = {
               1: setServer,
               2: addPeer,
               3: authReq,
               4: sendData,
               5: listIoTLedger,
               6: listBlockLedger,
               7: listPeers,
               8: newKeyPair,
               9: automa,
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
        print("5 - List IoT Ledger from connected Gateway")
        print("6 - List Block Ledger for a given IoT Block")
        print("7 - List PEERS")
        print("8 - Recreate Device KeyPair")
        print("9 - Run a batch operation...")
        print("10 - Create Merkle Tree for a given block")
        try:
            mode = int(raw_input('Input:'))
        except ValueError:
            print "Not a number"
        if (mode == 0):
            break
        options[mode]()


if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python deviceSimulator.py TBD")
        quit()
    os.system("clear")
    main()
