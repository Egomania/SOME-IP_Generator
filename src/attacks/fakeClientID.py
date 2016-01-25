
from src import Msg
from src.attacks import AttackerHelper

def fakeClientID(a):
    """ Attack that sends an arbitrary SOME/IP Packet using the own configuration (IP and MAC) but impersonates with another valid client id. """
    victim = AttackerHelper.selectVictim(a.clientConfigs)
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

def doAttack(curAttack, msgOrig, a, attacksSuc):

    RetVal = {}

    if a.verbose:
        print ('Fake Client ID Attack')

    msg = fakeClientID(a)
    if a.verbose:
        print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)

    RetVal['msg'] = msg
    RetVal['attackOngoing'] = False
    RetVal['dropMsg'] = False
    RetVal['counter'] = attacksSuc + 1

    return RetVal
    
