
import copy

from src import Msg
from src.attacks import AttackerHelper

def disturbTiming(a):
    """ Selects a device that sends time sensitive messages from configuration and sends an additional arbitrary but correct SOME/IP Packet to disturb the timing of the victim."""
    toremove = []
    preselect = copy.deepcopy(a.clientConfigs)
    for client in preselect:
        
        services = preselect[client]['service']
        
        for service in services:
            
            for method in service['method']:
                if not method['timesensitive']:
                    service['method'].remove(method)
            if len(service['method']) == 0:
                services.remove(service)
        if len(services) == 0:
            toremove.append(client)

    for client in toremove:
        del preselect[client]
    
    victim = AttackerHelper.selectVictim(preselect)
    timestamp = None
    msg = Msg.Msg(victim['client'], victim['server'], victim['msg'], timestamp)
    return msg


def doAttack(curAttack, msgOrig, a, attacksSuc):

    RetVal = {}

    if a.verbose:
        print ('Disturb Timing Attack')

    msg = disturbTiming(a)

    if a.verbose:
        print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)

    RetVal['msg'] = msg
    RetVal['attackOngoing'] = False
    RetVal['dropMsg'] = False
    RetVal['counter'] = attacksSuc + 1

    return RetVal
    
