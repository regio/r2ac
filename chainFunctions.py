import time

import BlockHeader
import Transaction
import criptoFunctions

BlockHeaderChain = []


def startBlockChain():
    BlockHeaderChain.append(getGenesisBlock())


def createNewBlock(devPubKey, gwPvt):
    newBlock = generateNextBlock("new block", devPubKey, getLatestBlock(), gwPvt)
    addBlockHeader(newBlock)
    return newBlock


def addBlockHeader(newBlockHeader):
    global BlockHeaderChain
    BlockHeaderChain.append(newBlockHeader)


def addBlockTransaction(block, transaction):
    block.transactions.append(transaction)


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


def getBlockchainSize():
    global BlockHeaderChain
    return len(BlockHeaderChain)


def getFullChain():
    return BlockHeaderChain


def getBlockByIndex(index):
    return BlockHeaderChain[index]


def getGenesisBlock():
    k = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM39ONP614uHF5m3C7nEh6XrtEaAk2ys
LXbjx/JnbnRglOXpNHVu066t64py5xIP8133AnLjKrJgPfXwObAO5fECAwEAAQ==
-----END PUBLIC KEY-----"""
    inf = Transaction.Transaction(0, "0", "0", "0", '')
    blk = BlockHeader.BlockHeader(0, "0", 1465154705, inf,
                                        "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", k)
    return blk


def generateNextBlock(blockData, pubKey, previousBlock, gwPvtKey):
    nextIndex = previousBlock.index + 1
    nextTimestamp = time.time()
    nextHash = criptoFunctions.calculateHash(nextIndex, previousBlock.hash, nextTimestamp, pubKey);
    sign = criptoFunctions.signInfo(gwPvtKey, nextHash)
    inf = Transaction.Transaction(0, nextHash, nextTimestamp, blockData, sign)
    return BlockHeader.BlockHeader(nextIndex, previousBlock.hash, nextTimestamp, inf, nextHash, pubKey);
