"""
Client module that sends reuqests and notifications to servers.
"""

import multiprocessing
import random
import time 

from src import Configuration
from src import Msg      
from src import SomeIPPacket

# everything a Client needs is packed bundled into Client-Class
class Client(object):

    """
    Initialization of the client class.

    :param config: Own client configuration.
    :param q: Own queue for receiving messages from servers.
    :param writer: Queue for writing out a packet.
    :param serverQueues: Queues of all available servers.
    :param stopQueues: A DONE is sent to this queue if on q a DONE is received.
    :param counter: Number of times all configured sending methods are used.
    :param attackers: Attacker Queue as the attacker is implemented as MitM.
    :param verbose: If set to True, more output is printed, default=False

    """
    def __init__(self, config, q, writer, serverQueues, stopQueue, counter, attackers, verbose=False):
        # own Configuration of the client 
        self.config = config 
        # each Client has a queue for incomming messages, e.g. from Servers
        self.ownQueue = q 
        # Queue to push the outgoing messages to
        self.writerQueue = writer
        # all serverQueues to push the messages to them
        self.serverQueues = serverQueues
        # when all messages to generate are pushed, a 'Done' is sent to the stopQueue
        self.stopQueue = stopQueue
        # number of packages to generate
        self.counter = counter
        self.sessionIDInit = 0x01
        self.sessionID = 0x01
        self.attackers = attackers
        # for getting Information about process, this value as to be set to True
        self.verbose = verbose

    def setName(self, name):
        """ Setter for client name. """
        self.name = name
    
    def setClientID(self, clientID):
        """ Setter for client IDs. """
        self.clientID = clientID


def getCurrentSessionID(key, sharedDict, sessionIDInit):
    """ returns the session ID for a specific server, method, service pair, initializes the session id if not available in the state, yet """
    if key not in sharedDict:
        idsUsed = []
        idsUsed.append(sessionIDInit)
        sharedDict[key] = idsUsed
        return sessionIDInit
    else:
        idsUsed = sharedDict[key]
        for i in range (0x01, 0xFFFF):
            if i not in idsUsed:
                idsUsed.append(i)
                sharedDict[key] = idsUsed
                return i

def incSessionID(sessionID):
    if sessionID == 0xFFFF:
        return 0x1
    else:
        return sessionID + 1

def setNewTimestamp(timestamp, serviceID, methodID, c):
    service = getUsedService(c.config['service'], serviceID)
    method = getUsedMethod(service['method'], methodID)
    
    minVal = method['resendMin']
    maxVal = method['resendMax']

    ts = timestamp + random.uniform(minVal, maxVal)

    return ts

def deleteUsedSessionID(sharedDict, server, service, method, session, c):
    """ Deletes the state and the session id, in case a response was received. """
    if c.verbose:
        print (c.name, ' - Delete free Session ID: ',session, ' from: ', sharedDict)
    indexToRemove = sharedDict[(server, service, method)].index(session)
    if c.verbose:
        print (c.name,' - Index to remove: ', indexToRemove)
    newList = sharedDict[(server, service, method)]
    del newList[indexToRemove]
    sharedDict[(server, service, method)] = newList
    if c.verbose:
        print (c.name, '- new shared dict: ', sharedDict[(server, service, method)])

def sendMsg(c, msg):
    c.attackers.put(msg)
    

def checkForResponse(server, service, method, session, state, message, ts, c):
    """ checks whether or not the incomming message is of type RESPONSE, in case an ERROR was received the message is resend """
    name = multiprocessing.current_process().name
    entry = (server, service, method, session)
    if (entry in state) and (message['type'] == SomeIPPacket.messageTypes['RESPONSE']):
        return True

    if (entry in state) and (message['type'] == SomeIPPacket.messageTypes['ERROR']):
        timestamp = setNewTimestamp(ts, service, method, c)
        resendMessage = message
        message['type'] = SomeIPPacket.messageTypes['REQUEST']
        message['ret'] = SomeIPPacket.errorCodes['E_OK']
        msg = Msg.Msg(c.name, server, resendMessage, timestamp)
        sendMsg(c, msg)
        if c.verbose:
            print (name, '- GOT an ERROR!!! - Try Resend')
            print (name, state)
        return False

    else:
        if c.verbose:
            print (name, ' - Unassignable Packet (Maybe Attack) - ', server, service, method, session, state, message)
            print (name, state)
        return False

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

def setTimestamp(timestamps, serviceIdUsed, methodIdUsed, method):
    oldts = timestamps[(serviceIdUsed, methodIdUsed)]
    interval = method['interval']
    minVal = interval[0]
    maxVal = interval[1]
    newts = oldts + random.uniform(minVal, maxVal)
    timestamps[(serviceIdUsed, methodIdUsed)] = newts
    return newts

def waitForIncomming(c, sharedDict, state, lock):
    """ own thread waiting for incomming messages (responses or errors) while the main thread is sending more packets """
    name = multiprocessing.current_process().name

    stillWait = True

    RequestCounter = 0
    ResponseCounter = 0

    while (True):

        if c.verbose:
            print (name, state)

        if (not stillWait) and (not state):
            print (name, ' - FINISHED - for: ', c.name)
            break

        msg = c.ownQueue.get()

        if (msg == 'Done'):
            stillWait = False
            continue

        service = msg.message['service']
        method = msg.message['method']
        session = msg.message['session']

        # own sent messages
        if (c.name == msg.sender):
            continue
        
        # server messages
        server = msg.sender
        if (checkForResponse(server, service, method, session, state, msg.message, msg.timestamp, c)):
            ResponseCounter = ResponseCounter + 1
            if c.verbose:
                print (name, ' - ResponseCounter: ', ResponseCounter)
                print (name, ' - Waiting for: LOCK (Session ID, State SharedMEM)')
            lock.acquire()
            if c.verbose:
                print (name, ' - Got LOCK: LOCK (Session ID, State SharedMEM)')
            del state[(server, service, method, session)]
            deleteUsedSessionID(sharedDict, server, service, method, session, c)
            lock.release()
            if c.verbose:
                print (name, ' - Release LOCK: LOCK (Session ID, State SharedMEM)')
        else:
            if c.verbose:
                print (name, ' - Got Non-Response - ', msg.sender, state, msg.message)


# own config, own queue, writer queue to send all messages, server queues for communication, stop queue when finished, counter as packet number to generate
def client(c):
    """worker function, that initializes the client and sends the configured number of packets, for each sent REQUEST state generated"""

    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    sharedDict = manager.dict()
    state = manager.dict()

    name = multiprocessing.current_process().name
    c.setName(name)
    services = c.config['service']
    clientID = c.config['clientID']
    c.setClientID(clientID)
    timestamp = time.time()

    # initiate all needed timestamps
    timestamps = {}
    for serviceToUse in services:
        serviceIdUsed = serviceToUse['id']
        for methodToUse in serviceToUse['method']:
            methodIdUsed = methodToUse['id']
            timestamps[(serviceIdUsed, methodIdUsed)] = timestamp

    print (c.name, ' - Starting with ClientID: ', c.clientID)

    if c.verbose:
        print (name, 'Starting with services: ', services)

    ownQueue = multiprocessing.Process(target=waitForIncomming, name=name+"Queue", args=(c, sharedDict, state, lock ))
    ownQueue.start()
    
    for i in range(0,c.counter):
        if c.verbose:   
            print (name, ' - Generate Packets in RUN: ', i)

        # go through all available service and methods
        for serviceUsed in services:
            # service related
            serviceIdUsed = serviceUsed['id'] 
                                     
            for methodUsed in serviceUsed['method']:
                # method related
                methodIdUsed = methodUsed['id']
                # server related
                servers = serviceUsed['server']
                serverNumUsed = random.randint(0,len(servers)-1)
                serverIdUsed = servers[serverNumUsed] 

                # putting everything together
                message = {}
                # set service/ method/ clientID
                message['service'] = serviceIdUsed       
                message['method'] = methodIdUsed
                message['client'] = c.clientID                
                # set session ID
                if (methodUsed['type'] == SomeIPPacket.messageTypes['REQUEST_NO_RETURN']) or (methodUsed['type'] == SomeIPPacket.messageTypes['NOTIFICATION']):
                    c.sessionID = incSessionID(c.sessionID)
                    message['session'] = c.sessionID
                elif (methodUsed['type'] == SomeIPPacket.messageTypes['REQUEST']):
                    # do some LOCKING here START
                    if c.verbose:
                        print (name, ' - Waiting for: LOCK (Session ID, State SharedMEM)')
                    lock.acquire()
                    if c.verbose:
                        print (name, ' - Got LOCK: LOCK (Session ID, State SharedMEM)')
                    message['session'] = getCurrentSessionID((serverIdUsed, serviceIdUsed, methodIdUsed), sharedDict, c.sessionIDInit)
                    state[(serverIdUsed, serviceIdUsed, methodIdUsed, message['session'])] = 'pending'
                    lock.release()
                    if c.verbose:
                        print (name, ' - Released LOCK for: LOCK (Session ID, State SharedMEM)')
                    # do some LOCKING here - END
                else:
                    message['session'] = 0x0
                # set type/ protocol version/ interface version/ return code
                message['type'] = methodUsed['type']
                message['ret'] = SomeIPPacket.errorCodes['E_OK']
                message['proto'] = SomeIPPacket.VERSION
                message['iface'] = SomeIPPacket.INTERFACE

                #trigger errors (for Testing issues):
                #message['service'] = 987
                #message['method'] = 987
                #message['type'] = SomeIPPacket.messageTypes['RESPONSE']
                #message['type'] = 3
                #message['proto'] = 2
                #message['iface'] = 2

                if c.verbose:
                    print(name, ' - Generated Packet: ', message)

                timestamp = setTimestamp(timestamps, serviceIdUsed, methodIdUsed, methodUsed)
                msg = Msg.Msg(name, serverIdUsed, message, timestamp)

                if c.verbose:
                    print(name, ' - Generated Message: ', msg)

                sendMsg(c, msg)

    c.ownQueue.put('Done')
    ownQueue.join()
    print (name, 'Exiting')

    c.stopQueue.put(name)

    return
