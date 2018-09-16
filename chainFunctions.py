import time

import BlockHeader
import Transaction
import criptoFunctions

BlockHeaderChain = []


def startBlockChain():
    """ Add the genesis block to the chain """
    BlockHeaderChain.append(getGenesisBlock())

def createNewBlock(devPubKey, gwPvt, useConsensus, **kwargs):
    """ Receive the device public key and the gateway private key then it generates a new block \n
    @param devPubKey - Public key of the requesting device \n
    @param gwPvt - Private key of the gateway \n

    @return BlockHeader
    """
    blockType = kwargs.get('type', None)
    if (blockType):
        newBlock = generateNextBlock("new block", devPubKey, getLatestBlock(), gwPvt, type=blockType)
    else:
        newBlock = generateNextBlock("new block", devPubKey, getLatestBlock(), gwPvt)
    ##@Regio addBlockHeader is done during consensus! please take it off for running pbft
    
    if(not useConsensus):
        addBlockHeader(newBlock)

    return newBlock


def addBlockHeader(newBlockHeader):
    """ Receive a new block and append it to the chain \n
    @param newBlockHeader - BlockHeader
    """
    global BlockHeaderChain
    BlockHeaderChain.append(newBlockHeader)


def addBlockTransaction(block, transaction):
    """ Receive a block and add to it a list of transactions \n
    @param block - BlockHeader \n
    @param transaction - list of transaction
    """
    block.transactions.append(transaction)


def getLatestBlock():
    """ Return the latest block on the chain \n
    @return BlockHeader
    """
    global BlockHeaderChain
    return BlockHeaderChain[len(BlockHeaderChain) - 1]


def getLatestBlockTransaction(blk):
    """ Return the latest transaction on a block \n
    @return Transaction
    """
    return blk.transactions[len(blk.transactions) - 1]



def blockContainsTransaction(block, transaction):
    """ Verify if a block contains a transaction \n
    @param block - BlockHeader object \n
    @param transaction - Transaction object\n
    @return True - the transaction is on the block\n
    @return False - the transcation is not on the block
    """
    for tr in block.transactions:
        if tr == transaction:
            return True
    return False


def findBlock(key):
    """ Search for a specific block in the chain\n
    @param key - Public key of a block \n
    @return BlockHeader - found the block on the chain \n
    @return False - not found the block on the chain
    """
    global BlockHeaderChain
    for b in BlockHeaderChain:
        if (b.publicKey == key):
            return b
    return False


def getBlockchainSize():
    """ Return the amount of blocks on the chain \n
    @return int - length of the chain
    """
    global BlockHeaderChain
    return len(BlockHeaderChain)


def getFullChain():
    """ Return the entire chain\n
    @return BlockHeader[] - list of all blocks on the chain
    """
    return BlockHeaderChain

def getAllBlockVotes():
    return filter(lambda block: block.type == 1000, BlockHeaderChain)


def getBlockByIndex(index):
    """ Return the block on a specific position of the chain\n
    @param index - desired block position\n
    @return BlockHeader 
    """
    return BlockHeaderChain[index]



def getGenesisBlock():
    """ Create the genesis block\n
    @return BlockHeader - with the genesis block
    """
    k = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM39ONP614uHF5m3C7nEh6XrtEaAk2ys
LXbjx/JnbnRglOXpNHVu066t64py5xIP8133AnLjKrJgPfXwObAO5fECAwEAAQ==
-----END PUBLIC KEY-----"""
    inf = Transaction.Transaction(0, "0", "0", "0", '')
    blk = BlockHeader.BlockHeader(0, "0", 1465154705, inf,
                                        "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", k)
    return blk


def generateNextBlock(blockData, pubKey, previousBlock, gwPvtKey, **kwargs):
    """ Receive the information of a new block and create it\n
    @param blockData - information of the new block\n
    @param pubKey - public key of the device how wants to generate the new block\n
    @param previouBlock - BlockHeader object with the last block on the chain\n
    @param gwPvtKey - private key of the gateway\n
    @return BlockHeader - the new block
    """
    nextIndex = previousBlock.index + 1    
    nextTimestamp = time.time()
    #nextHash = criptoFunctions.calculateHash(nextIndex, previousBlock.hash, nextTimestamp, pubKey);
    previousBlockHash = criptoFunctions.calculateHashForBlock(previousBlock)
    nextHash = criptoFunctions.calculateHash(nextIndex, previousBlockHash, nextTimestamp, pubKey)
    sign = criptoFunctions.signInfo(gwPvtKey, nextHash)
    inf = Transaction.Transaction(0, nextHash, nextTimestamp, blockData, sign)

    blockType = kwargs.get('type', None)
    if (blockType):
        return BlockHeader.BlockHeader(nextIndex, previousBlockHash, nextTimestamp, inf, nextHash, pubKey, type=blockType)
    else:
        return BlockHeader.BlockHeader(nextIndex, previousBlockHash, nextTimestamp, inf, nextHash, pubKey)
