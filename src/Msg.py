class Msg(object):
    def __init__(self, sender, receiver, message, timestamp): 
        self.sender = sender 
        self.receiver = receiver 
        self.message = message
        self.timestamp = timestamp

    def getSender(self):
        return self.sender

    def getReceiver(self):
        return self.receiver

    def getMessage(self):
        return self.message

    def getTimestamp(self):
        return self.timestamp



