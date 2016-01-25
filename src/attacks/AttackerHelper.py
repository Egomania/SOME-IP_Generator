"""
Collection of helper functions to implement attacks.
"""

import random 

from src import SomeIPPacket

def createMsg(serviceIdUsed, methodIdUsed, clientID, methodType):
    """ 
    Create a message as part of class Message.

    :param serviceIdUsed: The service id that appears in the SOME/IP Packet.
    :param methodIdUsed: The method id that appears in the SOME/IP Packet.
    :param clientID: The client id that appears in the SOME/IP Packet as initiating participant.
    :param methodType: The method type that appears in the SOME/IP Packet.
    :returns: A dictionary of strings that can be used for the Message class.
    """
    message = {}
        
    message['service'] = serviceIdUsed       
    message['method'] = methodIdUsed
    message['client'] = clientID
        
    message['session'] = 0x01
    message['type'] = methodType
    message['ret'] = SomeIPPacket.errorCodes['E_OK']
    message['proto'] = SomeIPPacket.VERSION
    message['iface'] = SomeIPPacket.INTERFACE

    return message    

def chooseRandomServer(service):
    """ Choose a random server to pass the created message to. All configured server can appear here. """
    servers = service['server']
    serverNumUsed = random.randint(0,len(servers)-1)
    serverIdUsed = servers[serverNumUsed]
    return serverIdUsed    

def selectVictim(victims):
    """ Select a victim to attack and pepare all needed meta-data for the attack to be executed. """
    victim = {}

    victim['client'] = random.choice(list(victims.keys()))

    config = victims[victim['client']]
    services = config['service']
    clientID = config['clientID']

    # choose service
    serviceNumUsed = random.randint(0,len(services)-1)
    service = services[serviceNumUsed]
    serviceIdUsed = service['id']

    # choose method
    methods = service['method']
    methodNumUsed = random.randint(0,len(methods)-1)
    method = methods[methodNumUsed]
    methodIdUsed = method['id']
    
    # choose server
    victim['server'] = chooseRandomServer(service) 
    
    # putting everything together
    message = createMsg(serviceIdUsed, methodIdUsed, clientID, method['type'])

    victim['msg'] = message

    return victim
