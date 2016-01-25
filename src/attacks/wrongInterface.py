
from src import Msg
from src.attacks import AttackerHelper

def wrongInterface(a):
    """ Sends a valid message impersonating another device with the wrong interface Number 0x03. """
    victim = AttackerHelper.selectVictim(a.clientConfigs)
    victim['msg']['clientID'] = a.clientID
    victim['msg']['iface'] = 0x03
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

def doAttack(curAttack, msgOrig, a, attacksSuc):

    RetVal = {}

    if a.verbose:
        print ('Wrong Interface Attack')

    msg = wrongInterface(a)
    if a.verbose:
        print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)

    RetVal['msg'] = msg
    RetVal['attackOngoing'] = False
    RetVal['dropMsg'] = False
    RetVal['counter'] = attacksSuc + 1

    return RetVal
    
