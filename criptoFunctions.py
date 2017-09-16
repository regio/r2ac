import hashlib


def calculateHash(index, previousHash, timestamp, key):
    shaFunc = hashlib.sha256()
    shaFunc.update((str(index)+str(previousHash)+str(timestamp)+key).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

def calculateHashForBlock(block):
    return calculateHash(block.index, block.previousHash, block.timestamp, block.publicKey)
