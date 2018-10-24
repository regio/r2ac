import Pyro4
import json
from flask import Flask, request, jsonify
import urllib
import sys
import socket

#############################################################################
#############################################################################
#########################    REST FAKE API  #################################
#############################################################################
#############################################################################

fname = socket.gethostname()

app = Flask(__name__)

r2acSharedInstance = ""

# Route paths
createBlockPath = '/createBlock'
votePath = '/vote'
votesByUserPath = '/votesBy'
votesToNewsPath = '/votesTo/<newsURL>'
getPopularNewsPath = '/popularNews/<quantity>'
allVotesPath = '/allVotes'

# Request keys
kUserPublicKey = 'userPublicKey'
kEncryptedVote = 'encryptedVote'
kNewsURL = 'newsURL'
kDate = 'date'
kPopularNewsQuantity = 'quantity'

# Response keys
kAESKey = 'aesKey'

@app.route(allVotesPath)
def getAllVotes():
    allTransactions = r2acSharedInstance.getAllTransactionsData()
    return jsonify(allTransactions)

@app.route(getPopularNewsPath)
def getPopularNews(quantity):

    allTransactions = r2acSharedInstance.getAllTransactionsData()
    allNewsRepeated = [i[kNewsURL] for i in allTransactions]
    allNewsUnique = set(allNewsRepeated)

    print(allNewsRepeated)
    print(allNewsUnique)

    newsVotes = []
    for news in allNewsUnique:
        votes = filter(lambda vote: vote[kNewsURL] == news, allTransactions)
        voteCount = len(votes)
        newsVotes.append((news, voteCount))

    # sort the list in ascending order
    newsVotes = sorted(newsVotes)
    onlyNews = [i[0] for i in newsVotes]

    return jsonify(onlyNews[:int(quantity)])


@app.route(createBlockPath, methods=['POST'])
def addBlock():
    """
    A POST method at {createBlockPath} to enable the creation of a block in the chain.\n

    Call this method before adding any transaction to establish an identification.\n
    A block is created using a public key - RSA 1024\n

    Parameters POST body
    -------
    arg: Dictionary
        {kUserPublicKey}: str
            The public key - RSA 1024

    Returns
    -------
    arg: Dictionary
        {kAESKey}: str
            The 32 bytes AES server communication key encrypted using raw RSA with the given public key
    
    500 Error - For Invalid key format
    """
    print("--------Received create block request!!")

    pubKey = request.values[kUserPublicKey]
    aesKey = r2acSharedInstance.addBlockForVote(pubKey)

    if (aesKey == 10):
        print("Invalid public key format")
        return "", "500 " + str(aesKey)
    else:
        return jsonify({kAESKey: aesKey})

@app.route(votePath, methods=['POST'])
def addVote():
    """
    A POST method at {votePath} to enable the creation of a vote\n
    
    Before adding a vote, it is necessary to create a block in the chain (by making a POST request at {createBlockPath}) as a vote is represented as a transaction inside a block.\n
    
    Parameters POST body
    -------
    arg: Dictionary
        {kUserPublicKey}: str
            The public key(RSA 1024)
        {kEncryptedVote}: str
            A dictionary encrypted(AES CBC Padding PKCS7) with the 32 bytes AES server communication key(received after creation of block)
                vote: base64Encoded str loadable as json dictionary
                    userPublicKey: str
                    vote: Boolean
                    newsURL: str
                signature: base64Encoded str
                    The vote dictionary signed with the private key(RSA 1024)

    Returns
    -------
    200 - Success
    500 - Error with statusMessage indicating error
        11 - No block found for given public key
        12 - No communicatino key (AES) found for given public key
        13 - Invalid signature
    """
    print("Received vote request")

    pubKey = request.values[kUserPublicKey]
    encryptedVote = request.values[kEncryptedVote]
    
    result = r2acSharedInstance.addVoteTransaction(pubKey, encryptedVote)

    if (result == 200):
        print("Successfully added")
        return jsonify(), 200

    if (result == 11):
        print("No block found for given public key")
        return "", "500 " + str(result)
    if (result == 12):
        print("No communication key found for given public key")
        return "", "500 " + str(result)
    if (result == 13):
        print("Invalid signature")
        return "", "500 " + str(result)

    print("Unhandled error!")
    return jsonify(), 500

@app.route(votesByUserPath)
def getAllVotesBy():
    """
    A GET method at {votesByUserPath} to get all votes by given public key of user\n
    
    Parameters GET
    -------
    {kUserPublicKey}: str
        The public key(RSA 1024) encoded with utf8
        
    Returns
    -------
    arg: [Dictionary]
        The votes made by the user at given public key
        userPublicKey: str
        vote: Boolean
        newsURL: str
    """
    print("Received all votes by user request")
    
    encodedUserPubKey = request.args.get(kUserPublicKey)
    userPublicKey = urllib.unquote(encodedUserPubKey).decode('utf8')
    allVotes = r2acSharedInstance.findDataOf(userPublicKey)
    
    return jsonify(allVotes)

@app.route(votesToNewsPath)
def getAllVotesTo(newsURL):
    """
    A GET method at {votesToNewsPath} to get all votes to given given news\n
    
    Parameters GET
    -------
    {kNewsURL}: str
        The news URL
        
    Returns
    -------
    arg: [Dictionary]
        The votes made by the user at given public key
        userPublicKey: str
        vote: Boolean
        newsURL: str
    """
    print("Requested all votes to news")

    allVotes = r2acSharedInstance.getAllTransactionsData()
    filteredVotes = filter(lambda vote: vote[kNewsURL] == newsURL, allVotes)

    return jsonify(filteredVotes)

def main():
    loadConnection()
    #runs flask
    app.run(host='0.0.0.0',port=5000)

def loadConnection():
    """ Load the URI of the connection  """
    global r2acSharedInstance
    fname = socket.gethostname()
    text_file = open(fname, "r")
    uri = text_file.read()
    print(uri)
    r2acSharedInstance = Pyro4.Proxy(uri)
    text_file.close()

if __name__ == '__main__':
    main()
