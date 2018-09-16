import Pyro4
import logging as logger
import json
from flask import Flask, request, jsonify
import Transaction
import chainFunctions
import base64
import Transaction
import DeviceInfo
import BlockHeader
import urllib

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
    print("--------Got to create block request!!")
    pubKey = request.values['userPublicKey']
    aesKey = r2acSharedInstance.addBlock(pubKey)
    print(aesKey)
    return jsonify(aesKey=aesKey, success=True)

@app.route('/vote', methods=['POST'])
def addVote():
    print("Received vote request for public key: ")
    pubKey = request.values[kUserPublicKey]
    print(pubKey)
    encryptedVote = request.values[kEncryptedVote]
    print("encryptedVote")
    print(encryptedVote)
    
    result = r2acSharedInstance.addVoteTransaction(pubKey, encryptedVote)

    if (result == 200):
        return jsonify(success=True), 200
    else:
        return jsonify(result), 400

@app.route("/votesBy")
def getAllVotesBy():
    print("Requested all votes by user")
    encodedUserPubKey = request.args.get('userPublicKey')
    userPublicKey = urllib.unquote(encodedUserPubKey).decode('utf8')
    #get block by user public key
    allVotes = r2acSharedInstance.findDataOf(userPublicKey)
    #get all transactions
    # transactions = block.transactions
    # #decripty transactions and retrieve data
    # blocksJSONED = map(lambda transaction: json.loads(transaction.data.data), transactions)
    print(allVotes)
    return jsonify(allVotes)

@app.route("/votesTo/<newsURL>")
def getAllVotesTo(newsURL):
    print("Requested all votes to news")
    #get all votes
    allVotes = r2acSharedInstance.getAllTransactionsData()
    print(allVotes)
    filteredVotes = filter(lambda vote: vote['newsURL'] == newsURL, allVotes)
    #return
    return jsonify(filteredVotes)

uri = "PYRO:obj_9563bc9446f848f6843454405d6ac45e@192.168.25.7:56085"
r2acSharedInstance = Pyro4.Proxy(uri)

#runs flask
app.run()
