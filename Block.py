class Block:
    def __init__(self, index, previousHash, timestamp, info, hash, publicKey):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.info = []
        self.info.append(info)
        self.hash = hash
        self.publicKey = publicKey

    def __str__(self):
        return "%s,%s,%s,%s,%s" % (str(self.index), str(self.previousHash), str(self.timestamp), str(self.hash), str(self.publicKey))

    def __repr__(self):
        return "<%s, %s, %s, %s, %s>" % (str(self.index), str(self.previousHash), str(self.timestamp), str(self.hash), str(self.publicKey))