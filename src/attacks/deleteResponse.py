
import copy
import random

from src import Msg
from src import SomeIPPacket
from src.attacks import AttackerHelper


def doAttack(curAttack, msgOrig, a, attacksSuc):

    RetVal = {}

    if a.verbose:
        print ('Delete Response Attack')

    if (msgOrig.message['type'] == SomeIPPacket.messageTypes['RESPONSE']):
        if a.verbose:
            print ('Successfully Deleted Response.')
            print ('MALICIOUS MSG: ', msgOrig.message, ' FROM=', msgOrig.sender, ' TO=', msgOrig.receiver)
        RetVal['msg'] = 'Forward'
        RetVal['attackOngoing'] = False
        RetVal['dropMsg'] = True
        RetVal['counter'] = attacksSuc + 1

    else:
        RetVal['msg'] = None
        RetVal['attackOngoing'] = True
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc
    

    return RetVal
    
