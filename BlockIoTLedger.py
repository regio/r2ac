class BlockIoTLedger:
    def __init__(self, index, previousHash, timestamp, block, hash, publicKey):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.blockLedger = []
        self.blockLedger.append(block)
        self.hash = hash
        self.publicKey = publicKey

    def __str__(self):
        return "%s,%s,%s,%s,%s,%s" % (str(self.index), str(self.previousHash), str(self.timestamp), str(self.blockLedger), str(self.hash), str(self.publicKey))

    def __repr__(self):
        return "<%s, %s, %s, %s, %s, %s>" % (str(self.index), str(self.previousHash), str(self.timestamp), str(self.blockLedger), str(self.hash), str(self.publicKey))