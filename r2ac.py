from flask import Flask, request
from os import listdir
from os.path import isfile, join

#import chainFunctions
import sys
import hashlib
import logging
import logging.config

logging.config.fileConfig('logging.conf')
# create logger
logger = logging.getLogger(__name__)

app = Flask(__name__)
peers = []
IoTLedger = []

#IoTLedger.append(chainFunctions.getGenesisBlock())

def addBlock(newIoTBlock):
    global IoTLedger
    # if (isValidNewBlock(newBlock, getLatestBlock())):
    logger.debug("[addBlock]Chain size:"+str(len(IoTLedger)))
    logger.debug("---------------------------------------")
    logger.debug("Block Header Size:"+str(len(str(newIoTBlock))))
    logger.debug("BH - index:"+str(len(str(newIoTBlock.index))))
    logger.debug("BH - previousHash:"+str(len(str(newIoTBlock.previousHash))))
    logger.debug("BH - timestamp:"+str(len(str(newIoTBlock.timestamp))))
    logger.debug("BH - hash:"+str(len(str(newIoTBlock.hash))))
    logger.debug("BH - publicKey:"+str(len(str(newIoTBlock.publicKey))))

    IoTLedger.append(newIoTBlock)

def main():
	logger.debug("asdf")
	logger.info("asdfinfo")
	logger.warn("asdfwarn")
	def runApp():
		app.run(host=sys.argv[1], port=3001, debug=True)
	runApp()


if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python r2ac.py <computer IP> <port>")
        quit()
    main()