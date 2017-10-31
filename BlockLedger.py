class BlockLedger:
    def __init__(self, index, previousHash, timestamp, data, signature):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.data = data
        self.signature = signature

    def __str__(self):
        return "%s,%s,%s,%s,%s" % (
        str(self.index), str(self.previousHash), str(self.timestamp), str(self.data), str(self.signature))

    def __repr__(self):
        return "%s,%s,%s,%s,%s" % (
        str(self.index), str(self.previousHash), str(self.timestamp), str(self.data), str(self.signature))

