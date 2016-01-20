""" 
The attacker module is used for simualtion predefined attacks. 
Messages between clients and servers are passed through the attacker and modified for attacks.
The attacker runs as a single process.

"""

import multiprocessing
import random 
import time     
import collections
import sys
import copy

import Msg 
import Configuration
import SomeIPPacket

class Attacker(object):

    """
    Initializes the Attacker.

    :param config: Own config
    :param clientConfigs: List of all available client configurations
    :param clientQueues: List of all available Client queues to pass messages to the client
    :param serverConfigs: List of all available server configurations
    :param serverQueues: List of all available Client queues to pass messages to the client
    :param writer: Writer queue to pass messages to that are send on the interface or written to the .pcap file
    :param conter: Number of attacks to be executed, can be set to 0 to create dumps without attacks
    :param attacks: List of attacks that can be executed during runtime, those values can be configured using the configuration file
    :param attackerQueue: Own queue messages from all clients and servers are passed to
    :param attackers: Other attackers whos messages can be ignored and are not attacked
    :param verbose: can be set to True for additional output, default=False
    :returns: configured Attacker Object
    """
    def __init__(self, config, clientConfigs, clientQueues, serverConfigs, serverQueues, writer, counter, attacks, attackerQueue, attackers, verbose=False):

        self.config = config
        self.clientConfigs = clientConfigs
        self.clientQueues = clientQueues

        self.serverConfigs = serverConfigs
        self.serverQueues = serverQueues

        self.attackerQueue=attackerQueue
        self.attackers = attackers        

        self.writerQueue = writer
        
        self.counter = counter
        self.attacks = attacks
        self.verbose = verbose

    def setIntervalMin(self, intervalMin):
        """ Set the minimum Interval an attacker will respond. The interval is given as int im ms."""
        self.intervalMin = intervalMin

    def setIntervalMax(self, intervalMax):
        """ Set the maximum Interval an attacker will respond.  The interval is given as int im ms."""
        self.intervalMax = intervalMax

    def setName(self, name):
        """ Set the internal Name of the attacker, useful in case more attackers in verbose mode are used.  The name is given as string. """
        self.name = name
    
    def setOwnClientID(self, clientID):
        """ Set the own client ID of the attacker as the attacker is a legitime part of the network. The client id is given as int. """
        self.clientID = clientID

def getUsedMethod(methods, methodIdUsed):
    for elem in methods:
        if elem['id'] == methodIdUsed:
            return elem

    return None

def getUsedService(services, serviceIdUsed):
    for elem in services:
        if elem['id'] == serviceIdUsed:
            return elem

    return None

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

def fakeClientID(a):
    """ Attack that sends an arbitrary SOME/IP Packet using the own configuration (IP and MAC) but impersonates with another valid client id. """
    victim = selectVictim(a.clientConfigs)
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

def wrongInterface(a):
    """ Sends a valid message impersonating another device with the wrong interface Number 0x03. """
    victim = selectVictim(a.clientConfigs)
    victim['msg']['clientID'] = a.clientID
    victim['msg']['iface'] = 0x03
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

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
    
    victim = selectVictim(preselect)
    timestamp = None
    msg = Msg.Msg(victim['client'], victim['server'], victim['msg'], timestamp)
    return msg

def randomErrorCode():
    """ Attack that replaces a correct Error Code with an arbitrary one that might is not correct for the situation. """
    errorCode = random.choice(list(SomeIPPacket.errorCodes.keys()))
    return SomeIPPacket.errorCodes[errorCode]

def fakeResponse(a, msgOrig):
    """ Removes a valid response from a server and replaces this response with an Error message. """
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

def sendErrorOnError(a, msgOrig):
    """ Answers with an Error message to a previous Error message. """
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

def str2bool(s):
    if s == 'True' or s == 'true':
        return True
    else:
        return False

def setTimestamp(timestamp, intervalMin, intervalMax):

    newTS = timestamp + random.uniform(intervalMin, intervalMax)

    return newTS

def doAttack(curAttack, msgOrig, a, attacksSuc):
    """ 
    Execute one of the predefined attacks that are configured to be executed. 
    
    :param curAttack: Choosen current attack.
    :param msgOrig: Original message the attack is applied to.
    :param a: Attacker Object containing all needed configurations and information.
    :param attacksSuc: Counter for successfully executed attacks.
    :returns: Triple(Boolean, Boolean, Int), First entry means that the original message is forwarded or not, The second part means attack was successfull, the last value indicates the number of successfully executed attacks.
    """
    
    if curAttack == 'fakeclientid':
        if a.verbose:
            print ('Fake Client ID Attack')
        msg = fakeClientID(a)
        if a.verbose:
            print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
        sendMsg(a, msg, msgOrig)
        attacksSuc = attacksSuc + 1
        return (False, False, attacksSuc)

    elif curAttack == 'wronginterface':
        if a.verbose:
            print ('Wrong Interface Attack')
        msg = wrongInterface(a)
        if a.verbose:
            print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
        sendMsg(a, msg, msgOrig)
        attacksSuc = attacksSuc + 1
        return (False, False, attacksSuc)

    elif curAttack == 'disturbtiming':
        if a.verbose:
            print ('Disturb Timing Attack')
        msg = disturbTiming(a)
        if a.verbose:
            print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
        sendMsg(a, msg, msgOrig)
        attacksSuc = attacksSuc + 1
        return (False, False, attacksSuc)

    elif curAttack == 'fakeresponse':
        if a.verbose:
            print ('Fake Response Attack')

        if msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST']:
            msg = fakeResponse(a, msgOrig)
            if a.verbose:
                print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
            sendMsg(a, msg, msgOrig)
            attacksSuc = attacksSuc + 1
            return (False, True, attacksSuc)
        else:
            return (True, False, attacksSuc)

    elif curAttack == 'senderroronerror':
        if a.verbose:
            print ('Send Error On Error Attack')
        if msgOrig.message['type'] == SomeIPPacket.messageTypes['ERROR']:
            msg = sendErrorOnError(a, msgOrig)
            if a.verbose:
                print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
            sendMsg(a, msg, msgOrig)
            attacksSuc = attacksSuc + 1
            return (False, False, attacksSuc)
        else:
            return (True, False, attacksSuc)


    elif curAttack == 'senderroronevent':
        if a.verbose:
            print ('Send Error On Event Attack')
        if (msgOrig.message['type'] == SomeIPPacket.messageTypes['NOTIFICATION']) or (msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST_NO_RETURN']):
            msg = sendErrorOnError(a, msgOrig)
            if a.verbose:
                print ('MALICIOUS MSG: ', msg.message, ' FROM=', msg.sender, ' TO=', msg.receiver)
            sendMsg(a, msg, msgOrig)
            attacksSuc = attacksSuc + 1
            return (False, False, attacksSuc)
        else:
            return (True, False, attacksSuc)

    elif curAttack == 'deleterequest':
        if a.verbose:
            print ('Delete Request Attack')
        if (msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST']):
            if a.verbose:
                print ('Successfully Deleted Request')
            forward (a, msgOrig)
            attacksSuc = attacksSuc + 1
            return (False, True, attacksSuc)
        else:
            return (True, False, attacksSuc)

    elif curAttack == 'deleteresponse':
        if a.verbose:
            print ('Delete Response Attack')
        if (msgOrig.message['type'] == SomeIPPacket.messageTypes['RESPONSE']):
            if a.verbose:
                print ('Successfully Deleted Attack')
            forward (a, msgOrig)
            attacksSuc = attacksSuc + 1
            return (False, True, attacksSuc)
        else:
            return (True, False, attacksSuc)
    else:
        return (False, False, attacksSuc)

def sendMsg(a, msg, msgOrig):
    """ The Message Object is sent to the writer queue putting the Packet into the trace. """
    msg.timestamp = setTimestamp(msgOrig.timestamp, a.intervalMin, a.intervalMax)
    a.writerQueue.put(msg)
    if msg.receiver in a.serverQueues:
        a.serverQueues[msg.receiver].put(msg)
    elif msg.receiver in a.clientQueues:
        a.clientQueues[msg.receiver].put(msg)
    else:
        print ('Unkown Receiver.')

def forward (a, msg):
    """ The message is going to be forwarded to its original receiver. """
    if msg.receiver in a.clientQueues:
        a.clientQueues[msg.receiver].put(msg)
    elif msg.receiver in a.serverQueues:
        a.serverQueues[msg.receiver].put(msg)
    elif msg.receiver in a.attackers:
        print (a.name, ' - Attack happend : ', msg.receiver)
    else:
        print ('Unkown Receiver.')

def attacker (a):
    """ Main method of the module that is initializing needed data and executing the attacking loop. """
    name = multiprocessing.current_process().name
    a.setName(name)
    a.setOwnClientID(a.config['clientID'])

    if a.attacks['min'] != None:
        intervalMin = int(a.attacks['min'])
    else:
        intervalMin = 0

    if a.attacks['max'] != None:
        intervalMax = int(a.attacks['max'])
    else:
        intervalMax = 10

    a.setIntervalMin(intervalMin)
    a.setIntervalMax(intervalMax)

    attacksConfigured = []

    fakeClientIDAttack = str2bool(a.attacks['fakeclientid'])
    wrongInterfaceAttack = str2bool(a.attacks['wronginterface'])
    disturbTimingAttack = str2bool(a.attacks['disturbtiming'])
    fakeResponseAttack = str2bool(a.attacks['fakeresponse'])
    sendErrorOnErrorAttack = str2bool(a.attacks['senderroronerror'])
    sendErrorOnEventAttack = str2bool(a.attacks['senderroronevent'])
    deleteRequestAttack = str2bool(a.attacks['deleterequest'])
    deleteResponseAttack = str2bool(a.attacks['deleteresponse'])

    if fakeClientIDAttack:
        attacksConfigured.append('fakeclientid')

    if wrongInterfaceAttack:
        attacksConfigured.append('wronginterface')

    if disturbTimingAttack:
        attacksConfigured.append('disturbtiming')

    if fakeResponseAttack:
        attacksConfigured.append('fakeresponse')

    if sendErrorOnErrorAttack:
        attacksConfigured.append('senderroronerror')

    if sendErrorOnEventAttack:
        attacksConfigured.append('senderroronevent')

    if deleteRequestAttack:
        attacksConfigured.append('deleterequest')

    if deleteResponseAttack:
        attacksConfigured.append('deleteresponse')

    if a.verbose:
        print (a.name, ' - Attacker started - ')
        print (a.name, ' - Client Configs: ', a.clientConfigs)
        print (a.name, ' - Server Configs: ', a.serverConfigs)
        print (a.name, ' - Attacks: ', a.attacks)

    attackOngoing = False
    dropMsg = False

    attacksSuc = 0

    while (True):

        msg = a.attackerQueue.get()
        dropMsg = False

        # Writer is done, attacker can close
        if (msg == 'Done'):
            print (a.name, 'GOT DONE msg')
            break

        # ignore attacker messages
        if (msg.receiver in a.attackers) or (msg.sender in a.attackers):
            continue

        if len(attacksConfigured) != 0:
            if not attackOngoing:

                attack = random.randint(1,a.counter)

                if attack == 1:
                    
                    if a.verbose:
                        print ('Do Attack now!')
                        
                    curAttack = random.choice(attacksConfigured)
                    attackResult = doAttack(curAttack, msg, a, attacksSuc) 
                    attackOngoing = attackResult[0]
                    dropMsg = attackResult[1]
                    attacksSuc = attackResult[2]

            else:           
                attackResult = doAttack(curAttack, msg, a, attacksSuc) 
                attackOngoing = attackResult[0]
                dropMsg = attackResult[1]
                attacksSuc = attackResult[2]

        if not dropMsg:
            forward(a, msg)
            a.writerQueue.put(msg)

    print (a.name, ' - BREAK - with ', attacksSuc, ' successful attacks')
    a.writerQueue.put('Done')
		
