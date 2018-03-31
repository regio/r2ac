import logging.config
import time

import BlockHeader
import Transaction
import criptoFunctions

# logging.config.fileConfig('temp/logging.conf')
# logger = logging.getLogger(__name__)


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
    #print("Create Block:")
    # print("Index:" + str(nextIndex) + " prevHash:" + str(previousBlock.hash) + " time:" + str(
    #     nextTimestamp) + " pubKey:")
    nextHash = criptoFunctions.calculateHash(nextIndex, previousBlock.hash, nextTimestamp, pubKey);
    #print ("Current block hash:"+str(nextHash))
    sign = criptoFunctions.signInfo(gwPvtKey, nextHash)
    inf = Transaction.Transaction(0, nextHash, nextTimestamp, blockData, sign)
    return BlockHeader.BlockHeader(nextIndex, previousBlock.hash, nextTimestamp, inf, nextHash, pubKey);
