class DeviceInfo:
    def __init__(self, deviceSignature, timestamp, data):
        self.deviceSignature = deviceSignature
        self.timestamp = timestamp
        self.data = data

    def __str__(self):
        return "%s,%s,%s" % (str(self.deviceSignature), str(self.timestamp), str(self.data))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
