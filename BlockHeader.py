class BlockHeader:
    def __init__(self, index, previousHash, timestamp, transaction, hash, publicKey, **kwargs):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.transactions = []
        self.transactions.append(transaction)
        self.hash = hash
        self.publicKey = publicKey
        blockType = kwargs.get('type', None)
        if (blockType):
            self.type = blockType
        else:
            self.type = 0

    def __str__(self):
        return "%s,%s,%s,%s,%s,%s" % (
            str(self.index), str(self.previousHash), str(self.timestamp), str(self.transactions), str(self.hash),
            str(self.publicKey), str(self.type))

    def __repr__(self):
        return "<%s, %s, %s, %s, %s, %s>" % (
            str(self.index), str(self.previousHash), str(self.timestamp), str(self.transactions), str(self.hash),
            str(self.publicKey), str(self.type))

    def strBlock(self):
        txt = "Index: " + str(self.index) + "\n Previous Hash: " + str(self.previousHash) + "\n Time Stamp: " + str(
            self.timestamp) + "\n Hash: " + str(self.hash) + "\n Public Key: " + str(
            self.publicKey) + "\n Number of transactions: " + str(len(self.transactions)) + "\n Type: " + str(self.type)
        return txt
