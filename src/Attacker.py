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
import imp

from src import Msg 
from src import Configuration
from src import SomeIPPacket

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

def randomErrorCode():
    """ Attack that replaces a correct Error Code with an arbitrary one that might is not correct for the situation. """
    errorCode = random.choice(list(SomeIPPacket.errorCodes.keys()))
    return SomeIPPacket.errorCodes[errorCode]


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
    
    RetVal = curAttack.doAttack(curAttack, msgOrig, a, attacksSuc)
    if RetVal['msg'] != None and RetVal['msg'] != 'Forward':
        sendMsg(a, RetVal['msg'], msgOrig)
    if RetVal['msg'] == 'Forward':
        forward (a, msgOrig)
    return (RetVal['attackOngoing'], RetVal['dropMsg'], RetVal['counter'])

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

def loadAttacks(attacksToUse):

    modules = []

    for attack in attacksToUse:

        selectedModulePath = 'src/attacks/' + attack + '.py'
        selectedModuleName = attack
        my_module = imp.load_source(selectedModuleName, selectedModulePath)
        modules.append(my_module)

    return modules

def attacker (a):
    """ 
    Main method of the module that is initializing needed data and executing the attacking loop. 
    The default value to set the minimum attacker response time is 0 ms.
    The default value to set the maximum attacker response time is 10 ms.
    Thoose values are used in case nothing is specified.
    """

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

    attacksToUse = [elem.strip() for elem in a.attacks['attacks'].split(',')]

    if a.verbose:
        print ('Configured Attacks: ', attacksToUse)    

    attacksConfigured = loadAttacks(attacksToUse)

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
		
