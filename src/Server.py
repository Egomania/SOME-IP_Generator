import multiprocessing
import random

import Configuration
import SomeIPPacket
import Msg
import time

class Server(object):
    def __init__(self, config, q, writer, clientQueues, attackers, stopQueue, verbose=False):
        # own Configuration of the server 
        self.config = config 
        # each Server has a queue for incomming messages, e.g. from Clients
        self.ownQueue = q 
        # Queue to push the outgoing messages to
        self.writerQueue = writer
        # all clientQueues to push the response messages to them
        self.clientQueues = clientQueues
        self.attackers = attackers
        # for getting Information about process, this value as to be set to True
        self.verbose = verbose
        self.stopQueue = stopQueue

    def setName(self, name):
        self.name = name


def msgTypeSupported(msgType):
    for elem in SomeIPPacket.messageTypes:
        if SomeIPPacket.messageTypes[elem] == msgType:
            return True

    return False

def returnRequestedMethod(service, methodID):
    for elem in service['methods']:
        if elem['id'] == methodID:
            return elem

    return None

def checkServiceAndMethodKnown(service, serviceID, methodID):

    if serviceID not in service:      
        return False
    else:
        if returnRequestedMethod(service[serviceID], methodID) == None:
            return False

    return True

def requestedMethodIsRequest(service, serviceID, methodID):
    if checkServiceAndMethodKnown(service, serviceID, methodID):
        curMethod = returnRequestedMethod(service[serviceID], methodID)
        if curMethod['type'] == SomeIPPacket.messageTypes['REQUEST']:
            return True

    return False    

def getProbValue(errorRate):
    val = random.random()
    if val < errorRate:
        return 1
    else:
        return 0

def generateRandomReply(errorRate, verbose, name):

    reply = {}

    value = getProbValue(errorRate)

    if verbose:
        print(name, ' - Given Error Rate: ', errorRate, ' choosen value', value)

    # create Error
    if value == 1:
        if verbose:
            print(name, ' - Send Error.')
        reply['type'] = SomeIPPacket.messageTypes['ERROR']
        errorValue = random.randint(0,5)
        if errorValue == 1:
            reply['ret'] = SomeIPPacket.errorCodes['E_NOT_OK']
        elif errorValue == 2: 
            reply['ret'] = SomeIPPacket.errorCodes['E_NOT_READY']
        elif errorValue == 3: 
            reply['ret'] = SomeIPPacket.errorCodes['E_NOT_REACHABLE']
        elif errorValue == 4: 
            reply['ret'] = SomeIPPacket.errorCodes['E_TIMEOUT']
        else:
            reply['ret'] = SomeIPPacket.errorCodes['E_MALFORMED_MESSAGE']


    # create normal Response
    else:
        if verbose:
            print(name, ' - Send normal Reply.')
        reply['type'] = SomeIPPacket.messageTypes['RESPONSE']
        reply['ret'] = SomeIPPacket.errorCodes['E_OK']

    return reply

def sendReply (msgType, msgRet, client, reply, timestamp, s):
    reply['type'] = msgType
    reply['ret'] = msgRet
    returnMsg = Msg.Msg(s.name, client, reply, timestamp)
    s.attackers.put(returnMsg)

def setTimeStamp(timestampOriginal, minVal, maxVal, s):

    timestamp = timestampOriginal + random.uniform(minVal,maxVal)

    if s.verbose:
        print (s.name, ' - Got Original Timestamp: ', timestampOriginal, ' using following settings: (',minVal,',',maxVal,') and Created: ', timestamp)


    return timestamp

def server(s):
    """service function"""
    name = multiprocessing.current_process().name
    s.setName(name)
    services = s.config
    
    print (s.name, ' Starting')

    if s.verbose:    
        print (s.name, 'Starting with services:', services)
    
    while (True):
        msg = s.ownQueue.get()
        if msg == 'Done':
            s.stopQueue.put('Done')
            break;
        
        client = msg.sender
        message = msg.message
        timestamp = setTimeStamp(msg.timestamp, s.config[message['service']]['min'], s.config[message['service']]['max'], s)
        reply = {}

        reply['service'] = message['service']
        reply['method'] = message['method']
        reply['client'] = message['client']
        reply['session'] = message['session']
        reply['proto'] = SomeIPPacket.VERSION
        reply['iface'] = SomeIPPacket.INTERFACE

        
        # check if some action is needed --> the method "requested" is of type REQUEST or a plain REQUEST is sent, but service or method is unknown
        if (not checkServiceAndMethodKnown(services, message['service'], message['method']) and message['type'] == SomeIPPacket.messageTypes['REQUEST']) or (requestedMethodIsRequest(services, message['service'], message['method'])):
            pass
        else:
            if s.verbose:
                print (s.name, 'IGNORE MESSAGE')
            continue

        # check for protocol version Number
        if message['proto'] != SomeIPPacket.VERSION:
            if s.verbose:
                print (s.name, 'Wrong Protocol Version.')
            sendReply(SomeIPPacket.messageTypes['ERROR'], SomeIPPacket.errorCodes['E_WRONG_PROTOCOL_VERSION'], name, client, reply, timestamp, writer, clientQueues[client])
            continue

        # check for interface version Number
        if message['iface'] != SomeIPPacket.INTERFACE:
            if s.verbose:
                print (s.name, 'Wrong Interface Version.')
            sendReply(SomeIPPacket.messageTypes['ERROR'], SomeIPPacket.errorCodes['E_WRONG_INTERFACE_VERSION'], client, reply, timestamp, s)
            continue

        # check if requested service is configured on server
        if message['service'] not in services:
            if s.verbose:
                print (s.name, 'Unsupported service.')
            sendReply(SomeIPPacket.messageTypes['ERROR'], SomeIPPacket.errorCodes['E_UNKNOWN_SERVICE'], client, reply, timestamp, s)
            continue
                
        curService = services[message['service']]   
        # check if requested method is supported
        if returnRequestedMethod(curService, message['method']) == None:
            if s.verbose:
                print (s.name, 'Unsupported Method.')
            sendReply(SomeIPPacket.messageTypes['ERROR'], SomeIPPacket.errorCodes['E_UNKNOWN_METHOD'], client, reply, timestamp, s)
            continue                       
                
        curMethod = returnRequestedMethod(curService, message['method'])

        # check if message Type is supported
        if (not msgTypeSupported(message['type'])):
            if s.verbose:
                print (s.name, 'IGNORE Unkown message Type.')
            continue

        # check for message Type, send Error if REQUEST is expected but not set
        if (message['type'] != SomeIPPacket.messageTypes['REQUEST'] and msgTypeSupported(message['type'])):
            if s.verbose:
                print (s.name, 'Wrong Message Type.')
            sendReply(SomeIPPacket.messageTypes['ERROR'], SomeIPPacket.errorCodes['E_WRONG_MESSAGE_TYPE'], client, reply, timestamp, s)
            continue

        generatedReply = generateRandomReply(s.config[reply['service']]['errorRate'], s.verbose, s.name)
        sendReply(generatedReply['type'], generatedReply['ret'], client, reply, timestamp, s)
        if s.verbose:            
            print (s.name, 'REPLY NEEDED')                    
                    

    print (s.name, 'Exiting')
