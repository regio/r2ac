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

@app.route("/votesBy/<userPublicKey>")
def getAllVotesBy(userPublicKey):
    #get block by user public key
    allVotes = r2acSharedInstance.findDataOf(userPublicKey)
    #get all transactions
    # transactions = block.transactions
    # #decripty transactions and retrieve data
    # blocksJSONED = map(lambda transaction: json.loads(transaction.data.data), transactions)

    return jsonify(allVotes)

@app.route("/votesTo/<newsURL>")
def getAllVotesTo(newsURL):
    print("Requested all votes to news")
    #get all votes
    allVotes = r2acSharedInstance.getAllTransactionsData()
    filteredVotes = filter(lambda vote: vote.newsURL == newsURL, allVotes)
    #return
    return jsonify(filteredVotes)

uri = "PYRO:obj_699bf42d89b44c60b8b4314d42147437@192.168.25.7:54158"
r2acSharedInstance = Pyro4.Proxy(uri)

#runs flask
app.run()
