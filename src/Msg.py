""" Message class to bundle all needed information to pass messages between devices. Provides initialization and getter methods."""

class Msg(object):

    """ 
    :param sender: Dictionary including all sender information.
    :param receiver: Dictionary including all receiver information.
    :param message: Dictionary including all message information.
    :param timestamp: Timestamp to be used when message is inserted into .pcap.
    """    

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



