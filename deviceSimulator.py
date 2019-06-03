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
    #randValue = Random.random.randrange(24)
    private = RSA.generate(1024)

    #private = RSA.generate(1024,randValue)
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
    #print("###addBlockonChain in devicesimulator, publicKey")
    #print(publicKey)
    serverAESEncKey = server.addBlock(publicKey)
    #print("###addBlockonChain in devicesimulator, serverAESEncKey")
    #print(serverAESEncKey)
    #while len(serverAESEncKey) < 10:
    #    serverAESEncKey = server.addBlock(publicKey)
    decryptAESKey(serverAESEncKey)
    #print("###after decrypt aes")

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
    #print("ServeAESKEY: ")
    #print(serverAESKey)
    encobj = criptoFunctions.encryptAES(toSend, serverAESKey)
    server.addTransaction(publicKey, encobj)

def sendDataSC(stringSC):
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data= timeStr + stringSC
    signedData = criptoFunctions.signInfo(privateKey,data)
    print("###Printing Signing Data before sending: "+signedData)
    print ("###Signature lenght: " + str(len(signedData)))
    toSend = signedData + timeStr + stringSC
    encobj = criptoFunctions.encryptAES(toSend, serverAESKey)
    server.addTransactionSC(publicKey, encobj)
    #server.addTransaction(toSend)

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
    server.showBlockLedger(int(index))

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
            #global serverAESKey
            #print("the size of the serverAESKey is: "+str(len(serverAESKey)))
            return #addBlockConsensusCandiate


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
            print("###send transaction")
            #sendData()
            while (not (server.isBlockInTheChain(publicKey))):
                continue
                #time.sleep(1)
            #print("#outside while in automa")
            bruteSend(tr)
    print("end of automa")


def merkle():
    """ Calculates the hash markle tree of the block """
    blk = int(input("Which block you want to create the merkle tree:"))
    server.calcMerkleTree(blk)#addBlockConsensusCandiate
    print ("done")

def newElection():
    server.electNewOrchestrator()
    return True

def defineConsensus():
    receivedConsensus = str(input('Set a consensus (PBFT, PoW, dBFT or Witness3: '))
    server.setConsensus(receivedConsensus) #server will set its consensus and send it to all peers
    print("Consensus " + receivedConsensus + " was defined" )
    return True

def createBlockForSC():
    newKeyPair()
    addBlockOnChain()
    while (not (server.isBlockInTheChain(publicKey))):
        continue
        # time.sleep(1)
    firstTransactionSC='{ "Tipo" : "", "Data": "", "From": "", "To" : "", "Root" : "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" }'
    sendDataSC(firstTransactionSC)

def showLastTransactionData():
    blockIndex = int(input('Type the index to show the last transaction data: '))
    lastDataTransactionData=server.showLastTransactionData(blockIndex)
    return lastDataTransactionData

def callEVM():
    # Create a TCP
    # IP socket
    global privateKey
    global publicKey
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # ROBEN
    # Coleta o data da ultima transacao um json
    ultimaTrans = showLastTransactionData()
    ultimaTransJSON = json.loads(ultimaTrans)

    print("###Insira os dados da chamada do contrato###")
    tipo=str(input("Type (1,2,3,4): "))
    data=str(input("Data (binary in hexa: "))
    origin = str(input("From account: "))
    dest= str(input("Destination account: "))

    transAtual = json.loads('{"Tipo":"%s","Data":"%s","From":"%s","To":"%s"}' % (tipo, data, origin, dest))

    #chamada =  '{"Tipo":"%s","Data":"%s","From":"%s","To":"%s","Root":"%s"}' % (transAtual['Tipo'], transAtual['Data'], transAtual['From'], transAtual['To'], ultimaTransJSON['Root'])
    chamada =  '{"Tipo":"%s","Data":"%s","From":null,"To":null,"Root":"%s"}' % (transAtual['Tipo'], transAtual['Data'], ultimaTransJSON['Root'])
    chamadaJSON =  json.loads(chamada)

    #chamada = '{"Tipo":"Exec","Data":"YAFgQFNgAWBA8w==","From":null,"To":null,"Root":null}'  # Comentar
    #chamadaJSON = json.loads(chamada)  # Comentar

    try:
        # Tamanho maximo do JSON 6 caracteres
        s.connect(('localhost', 6666))
        tamanhoSmartContract = str(len(chamada))
        for i in range(6 - len(tamanhoSmartContract)):
            tamanhoSmartContract = '0' + tamanhoSmartContract
        print("Enviando tamanho " + tamanhoSmartContract + "\n")
        # Envia o SC
        s.send(tamanhoSmartContract)
        time.sleep(1)
        # print(json.dumps(chamadaJSON))
        s.send(chamada)

        # Recebe tamanho da resposta
        tamanhoResposta = s.recv(6)
        print("Tamanho da resposta: " + tamanhoResposta)
        # Recebe resposta
        resposta = s.recv(int(tamanhoResposta))
        print(resposta + "\n")

        # Decodifica resposta
        respsotaJSON = json.loads(resposta)
        # print(respsotaJSON['Ret'])

        if respsotaJSON['Erro'] != "":
            print("Erro: Transacao nao inserida")
        elif chamadaJSON['Tipo'] == "Exec":
            print("Execucao, sem insercao de dados na blockchain")
        else:
            transacao = '{ "Tipo" : "%s", "Data": "%s", "From": "%s", "To" : "%s", "Root" : "%s" }' % (
            chamadaJSON['Tipo'], chamadaJSON['Data'], chamadaJSON['From'], chamadaJSON['To'], respsotaJSON['Root'])
            print("Transacao sendo inserida: %s \n" % transacao)
            # ROBENNNNN
            sendDataSC(transacao)
            # pass


    finally:
        print("fim\n")
        s.close()
    return True

def evmConnector():
    return True

def executeEVM():
    return True

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
               10: merkle,
               11: newElection,
                12: defineConsensus,
                13: createBlockForSC,
                14: showLastTransactionData,
                15: callEVM,
                16: evmConnector,
                17: executeEVM
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
        print("11 - Elect a new node as Orchestator (used for voting based consensus")
        print("12 - Set a consensus algorithm")
        print("13 - Create a block for Smart Contract")
        print("14 - Show data from last transaction from block Index")
        print("15 - Smart Contract inclusion")
        print("16 - EVM connector")
        print("17 - execute EVM code")

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
