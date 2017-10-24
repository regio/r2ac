import Info
import Block
import criptoFunctions
import time


from os import listdir
from os.path import isfile, join


# each file read will be mapped to an IoT Ledger Block
def bootstrapChain():

    folder = "./keys/"
    publicK= []

    for f in listdir(folder):
        if isfile(join(folder, f)):
            if f.startswith("public"):
                publicK.append(folder+f)
                fl = open(folder+f, 'r')
                x = fl.read() 
                print(x)

            if f.startswith("Gateway_private"):
                fl = open(folder+f, 'r')
                gwPvt = fl.read()
                #print gwPvt

            if f.startswith("Gateway_public"):
                fl = open(folder+f, 'r')
                gwPub = fl.read()
                #print gwPub

    #retrieve a list of files from keys folder
    #onlyFiles = [f for f in listdir("./keys/") if isfile(join("./keys", f))]

    #creates a list of files called public*
    #publicK = [f for f in onlyFiles if f.startswith("public")]
    return gwPvt, gwPub, publicK

def getGenesisBlock():
    k = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM39ONP614uHF5m3C7nEh6XrtEaAk2ys
LXbjx/JnbnRglOXpNHVu066t64py5xIP8133AnLjKrJgPfXwObAO5fECAwEAAQ==
-----END PUBLIC KEY-----"""
    inf = Info.Info(0, "0", "0", "0", '') 
    blk = Block.Block(0, "0", 1465154705, inf, "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", k)
    return blk

def generateNextBlock(blockData, pubKey, previousBlock):
    nextIndex = previousBlock.index + 1
    nextTimestamp = time.time()
    nextHash = criptoFunctions.calculateHash(nextIndex, previousBlock.hash, nextTimestamp, pubKey);
    #inf = Info.Info(0, blockData, '');
    inf = Info.Info(0, "0", "0", blockData, 'x') 
    return Block.Block(nextIndex, previousBlock.hash, nextTimestamp, inf, nextHash, pubKey);