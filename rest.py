import Pyro4
import logging as logger
import json
from flask import Flask, request, jsonify
import Transaction
import chainFunctions

#############################################################################
#############################################################################
#########################    REST FAKE API  #################################
#############################################################################
#############################################################################

app = Flask(__name__)

r2acSharedInstance = ""

kUserPublicKey = 'userPublicKey'
kEncryptedVote = 'encryptedVote'
kVote = 'vote'
kNewsURL = 'newsURL'
kAESKey = 'aesKey'
kDate = 'date'

@app.route('/createBlock', methods=['POST'])
def addBlock():
    logger.info("--------Got to create block request!!")
    pubKey = request.values['userPublicKey']
    aesKey = r2acSharedInstance.addBlock(pubKey)
    return jsonify(aesKey=aesKey, success=True)

@app.route('/vote', methods=['POST'])
def addVote():
    logger.info("Received vote request for public key: ")
    pubKey = request.values[kUserPublicKey]
    logger.info(pubKey)
    encryptedVote = request.values[kEncryptedVote]
    
    result = r2acSharedInstance.addVoteTransaction(pubKey, encobj)

    if (result == 200):
        return jsonify(result)
    else:
        return jsonify(result), 400

@app.route("/votesBy/<userPublicKey>")
def getAllVotesBy(userPublicKey):
    #get block by user public key
    block = chainFunctions.findBlock(userPublicKey)
    #get all transactions
    transactions = block.transactions
    #decripty transactions and retrieve data
    blocksJSONED = map(lambda transaction: json.loads(transaction.data.data), transactions)

    return jsonify(blocksJSONED)

@app.route("/votesTo/<newsURL>")
def getAllVotesTo(newsURL):
    #get all blocks
    chain = chainFunctions.getFullChain()

    if(chain):
        logger.info("---- chain")
        logger.info(chain)

    #get all transactions
    transactions = reduce(lambda allTransactions, block: allTransactions.extend(block.transactions), chain)
    logger.info("---- transactions")
    logger.info(chain)

    #decripty transactions
    allBlocks = map(lambda transaction: json.loads(transaction.data.data), transactions)
    #filter by newsURL
    filteredBlocks = filter(lambda block: block.newsURL == newsURL, blocks)
    #return
    return jsonify(filteredBlocks)

uri = "PYRO:obj_cab2f7ab38df4757ad35a671e3e51d4a@10.41.40.31:51578"
r2acSharedInstance = Pyro4.Proxy(uri)

#runs flask
app.run()