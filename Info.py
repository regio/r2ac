
class Info:
    def __init__(self, index, data, signature):
        self.index = index
        self.data = data
        self.signature = signature

    def __str__(self):
        return "%s,%s,%s" % (str(self.index), str(self.data), str(self.signature))

    def __repr__(self):
        return "%s,%s,%s" % (str(self.index), str(self.data), str(self.signature))