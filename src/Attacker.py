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
        self.intervalMin = intervalMin

    def setIntervalMax(self, intervalMax):
        self.intervalMax = intervalMax

    def setName(self, name):
        self.name = name
    
    def setOwnClientID(self, clientID):
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
    servers = service['server']
    serverNumUsed = random.randint(0,len(servers)-1)
    serverIdUsed = servers[serverNumUsed]
    return serverIdUsed        

def selectVictim(victims):
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
    
    victim = selectVictim(a.clientConfigs)
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

def wrongInterface(a):
    victim = selectVictim(a.clientConfigs)
    victim['msg']['clientID'] = a.clientID
    victim['msg']['iface'] = 0x03
    timestamp = None
    msg = Msg.Msg(a.name, victim['server'], victim['msg'], timestamp)
    return msg

def disturbTiming(a):
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
    errorCode = random.choice(list(SomeIPPacket.errorCodes.keys()))
    return SomeIPPacket.errorCodes[errorCode]

def fakeResponse(a, msgOrig):
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
    msg.timestamp = setTimestamp(msgOrig.timestamp, a.intervalMin, a.intervalMax)
    a.writerQueue.put(msg)
    if msg.receiver in a.serverQueues:
        a.serverQueues[msg.receiver].put(msg)
    elif msg.receiver in a.clientQueues:
        a.clientQueues[msg.receiver].put(msg)
    else:
        print ('Unkown Receiver.')

def forward (a, msg):
    if msg.receiver in a.clientQueues:
        a.clientQueues[msg.receiver].put(msg)
    elif msg.receiver in a.serverQueues:
        a.serverQueues[msg.receiver].put(msg)
    elif msg.receiver in a.attackers:
        print (a.name, ' - Attack happend : ', msg.receiver)
    else:
        print ('Unkown Receiver.')

def attacker (a):
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
		
