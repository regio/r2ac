import Pyro4
import os
import random
import sys
import time

import criptoFunctions

server = "localhost"
serverAESEncKey = ""
serverAESKey = ""
privateKey = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA7P6DKm54NjLE7ajy\nTks298FEJeHJNxGT+7DjbTQgJdZKjQ6X9lYW8ittiMnvds6qDL95eYFgZCvO22YT\nd1vU1QIDAQABAkBEzTajEOMRSPfmzw9ZL3jLwG3aWYwi0pWVkirUPze+A8MTp1Gj\njaGgR3sPinZ3EqtiTA+PveMQqBsCv0rKA8NZAiEA/swxaCp2TnJ4zDHyUTipvJH2\nqe+KTPBHMvOAX5zLNNcCIQDuHM/gISL2hF2FZHBBMT0kGFOCcWBW1FMbsUqtWcpi\nMwIhAM5s0a5JkHV3qkQMRvvkgydBvevpJEu28ofl3OAZYEwbAiBJHKmrfSE6Jlx8\n5+Eb8119psaFiAB3yMwX9bEjVy2wRwIgd5X3n2wD8tQXcq1T6S9nr1U1dmTz7407\n1UbKzu4J8GQ=\n-----END PRIVATE KEY-----\n"
publicKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"

def setServer():
    global server
    if sys.version_info < (3, 0):
        input = raw_input
    #server = raw_input('Gateway IP:')
    uri = input("Enter the uri of the gateway: ").strip()
    server = Pyro4.Proxy(uri)

def authReq():
    serverAESEncKey = server.auth(publicKey)
    # headers = {'Content-type': 'application/json'}
    # payload = {'publicKey': publicKey}
    # r = requests.post("http://" + server + ":3001/auth", data=json.dumps(payload), headers=headers)
    # serverAESEncKey = r.text
    print("AES key encrypted received from server")
    decryptAESKey(serverAESEncKey)

def sendData():
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = temperature + timeStr
    signedData = criptoFunctions.signInfo(privateKey, data)
    toSend = signedData + timeStr + temperature
    encobj = criptoFunctions.encryptAES(toSend, serverAESKey)

    asdf = server.info(publicKey, encobj)

    # headers = {'Content-type': 'application/json'}
    # payload = {'publicKey': publicKey, 'EncObj': encobj}
    # r = requests.post("http://" + server + ":3001/info", data=json.dumps(payload), headers=headers)
    # asdf = r.text
    print("maybe worked " + asdf)

def decryptAESKey(data):
    global serverAESKey
    serverAESKey = criptoFunctions.decryptRSA2(privateKey, data)

def readSensorTemperature():
    temp = str(random.randint(-10, 40)) + " C"
    print("The device has read the temperature:" + temp)
    return temp

def addPeer():
    if sys.version_info < (3, 0):
        input = raw_input
    uri = input("Enter the PEER uri: ").strip()
    server.addPeer(uri)

def listIoTLedger():
    server.showIoTLedger()

def listBlockLedger():
    index = input("Which IoT Block do you want to print?")
    server.showBlockLedger(index)
#############################################################################
######################          Main         ################################
#############################################################################
def main():
    global server
    options = {
               1: setServer,
               2: addPeer,
               3: authReq,
               4: sendData,
               5: listIoTLedger,
               6: listBlockLedger
               }

    mode = -1
    while True:
        print("Choose your option [" + str(server) + "]")
        print("0 - Exit")
        print("1 - Set Server Address[ex:PYRO:chain.server@blablabala:00000]")
        print("2 - Add Peer")
        print("3 - Authentication Request")
        print("4 - DecriptReceivedAESKey - sign data - encrypt with AES key - Send to Gateway")
        print("5 - List IoT Ledger from connected Gateway")
        print("6 - List Block Ledger for a diven IoT Block")
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