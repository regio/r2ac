import Pyro4
import json
from flask import Flask, request, jsonify
import urllib
import sys

#############################################################################
#############################################################################
#########################    REST FAKE API  #################################
#############################################################################
#############################################################################

app = Flask(__name__)

r2acSharedInstance = ""

# Route paths
createBlockPath = '/createBlock'
votePath = '/vote'
votesByUserPath = '/votesBy'
votesToNewsPath = '/votesTo/<newsURL>'

# Request keys
kUserPublicKey = 'userPublicKey'
kEncryptedVote = 'encryptedVote'
kNewsURL = 'newsURL'
kDate = 'date'

# Response keys
kAESKey = 'aesKey'
kSuccess = 'success'

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
            
    """
    print("--------Received create block request!!")

    pubKey = request.values[kUserPublicKey]
    aesKey = r2acSharedInstance.addBlock(pubKey)

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
    arg: Dictionary
        {kSuccess}: Boolean
            Indicates the success of the request
    """
    print("Received vote request")

    pubKey = request.values[kUserPublicKey]
    encryptedVote = request.values[kEncryptedVote]
    
    result = r2acSharedInstance.addVoteTransaction(pubKey, encryptedVote)

    if (result == 200):
        return jsonify({kSuccess: True}), 200
    else:
        return jsonify({kSuccess: False}), 500

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
    uri = ""
    try:
        uri = str(input('Enter the blockchain address: '))
    except ValueError:
        print ("Not acceptable")

    print(uri)
    global r2acSharedInstance
    r2acSharedInstance = Pyro4.Proxy(uri)
    #runs flask
    app.run()


if __name__ == '__main__':
    main()
