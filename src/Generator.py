""" 
Main Module of the project. 
The configuration from config/config.ini is parsed.
All needed devices (client, server, attacker) are initialized and started as seperate processes.
"""

import multiprocessing
import time
import xml.etree.ElementTree as ET
import random
import configparser
import sys

import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

import SomeIPPacket
import Client
import Server
import Configuration
import Msg
import Attacker

# Expects: own Queue, Number of incomming 'Done's, ServerDeviceConfiguration, ClientDeviceConfiguration
def writer(q, serverCount, attackerList, attackerQueue, ServerDeviceConfig, ClientDeviceConfig, interface, pcap):
    """ 
    Used for a seperate writer process that is getting all packets to be send and append them to the .pcap file configured.
    :param q: Own Queue to receive all packets forwarded by the attackers.
    :param serverCount: number of servers in the system. 
    :param attackerList: List of attackers in the system.
    :param attackerQueue: Message Queues of the attackers.
    :param ServerDeviceConfig: Server Device Configuration with needed meta data for sending packets.
    :param ClientDeviceConfig: Client Device Configuration (includes attacker device) with needed meta data for sending packets.
    :param interface: Interface to send the data.
    :param pcap: .pcap file to write the data.
    """

    deviceConfig = {}

    for key, value in ServerDeviceConfig.items():
        deviceConfig[key] = value
        
    for key, value in ClientDeviceConfig.items():
        deviceConfig[key] = value

    counter = 0

    start_time = time.time()

    if interface != None:
        sck = conf.L2socket(iface=interface)

    # wait fo incomming messages to prepare for sending
    while (True):
        msg = q.get()
        
        # attacker sending 'Done's in case all requests are processed
        if msg == 'Done':
            break
        else:
            # capture received messaged and transform into SomeIP packtes
            sender = {}
            sender['mac'] = deviceConfig[msg.sender]['mac']
            sender['ip'] = deviceConfig[msg.sender]['ip']
            sender['port'] = deviceConfig[msg.sender]['sendPort']
            receiver = {}
            receiver['mac'] = deviceConfig[msg.receiver]['mac']
            receiver['ip'] = deviceConfig[msg.receiver]['ip']
            receiver['port'] = deviceConfig[msg.receiver]['recPort']
            message = msg.message
            timestamp = msg.timestamp
            packet = SomeIPPacket.createSomeIP(sender, receiver, message)
            packet.time = timestamp

            counter = counter + 1

            if pcap != None:
                wrpcap(pcap, packet, append=True)

            if interface != None:
                sck.send(packet)
            

    print ('Writer Stoped By Attacker')

    stop_time = time.time()

    print ('Number of Packets generated: ', counter)

    print ('Time to generate Packets:', stop_time - start_time)

    print ('Writer Exiting')    

def stop(q, clientCounts, servers, serverQueues):
    """ 
    First Level of stopping all processes. 
    This function is running as a process and waits for all clients to be done (all required messages are sent and no state).
    In this case, a DONE message is sent to all servers to indicate that no more clients requests will arrive and they can shut down. 

    :param q: Own Queue to listen on incomming DONE messages.
    :param clientCounts: Number of expected DONE messages.
    :param servers: List of server instances.
    :param serverQueues: List of server queues.
    """

    counter = 0

    while (True):
        obj = q.get()
        counter = counter + 1
        print ("Clients Done:", counter)
        if (counter == clientCounts):
            for server in servers:
                serverQueues[server].put('Done')
            break;

    print ("Stop", 'Exiting')

def stop2(q, serverCounts, attackers, attackerQueue):
    """ 
    Second Level of stopping all processes. 
    This function is running as a process and waits for all servers to be done (server got a DONE message previously).
    In this case, a DONE message is sent to all attackers to indicate that no more packets will arrive and they can shut down. 

    :param q: Own Queue to listen on incomming DONE messages.
    :param serverCounts: Number of expected DONE messages.
    :param attackers: List of attacker instances.
    :param attackerQueue: List of attacker queues.
    """
    counter = 0

    while (True):
        obj = q.get()
        counter = counter + 1
        print ("Servers Done:", counter)
        if (counter == serverCounts):
            for attacker in attackers:
                attackerQueue.put('Done')
            break;

    print ("Stop", 'Exiting')

def str2bool(s):
    if s == 'True' or s == 'true':
        return True
    else:
        return False

if __name__ == '__main__':

    Config = configparser.ConfigParser()
    Config.read("config/config.ini")

    deviceFile = Config["Files"]['deviceFile']
    serviceFile = Config["Files"]['serviceFile']

    interface = Config["Pcap"].get('interface', None)
    pcap = Config["Pcap"].get('file', None)

    packetCount = int(Config["Pcap"].get('counter', 100))
    packetCountAttack = int(Config["Attacks"].get('counter', 1))
    attacks = Config._sections["Attacks"]

    clientVerbose = str2bool(Config["Verbose"].get('client', False))
    serverVerbose = str2bool(Config["Verbose"].get('server', False))
    attackerVerbose = str2bool(Config["Verbose"].get('attacker', False))

    tree = ET.parse('config/devices.xml')
    root = tree.getroot()

    clientList = []
    serverList = []
    attackerList = []

    for dev in root.iter('device'):
        if (dev.get('type') == 'client'):
            clientList.append(dev.get('name'))
        elif (dev.get('type') == 'server'):
            serverList.append(dev.get('name'))
        elif (dev.get('type') == 'attacker'):
            attackerList.append(dev.get('name'))
        else:
            print ("Error - unkown type")

    # List of processes of Entities
    servers = []
    clients = []
    attackers = []

    # Dict of Client/ServerObjects
    clientObjects = {}
    serverObjects = {}

    # Dict of configs
    clientConfigs = {}
    serverConfigs = {}
    attackerConfigs = {}

    # Dict of deviceConfig

    clientDeviceConfigs = {}
    serverDeviceConfigs = {}

    # dict of queues
    serverQueues = {}
    clientQueues = {}

    # list of all used queues
    queues = []

    # dedicated attacker queue
    attackerQueue = multiprocessing.Queue()
    queues.append(attackerQueue)

    #prepare all queues and configs

    for serverName in serverList:
        serverConfig = Configuration.getServerConfig(serverName, serviceFile, serverVerbose)
        serverConfigs[serverName] = serverConfig
        serverDeviceConfig = Configuration.getDeviceConfig(serverName, deviceFile, serverVerbose)
        serverDeviceConfigs[serverName] = serverDeviceConfig
        q = multiprocessing.Queue()
        queues.append(q)
        serverQueues[serverName] = q

    for clientName in clientList:
        clientConfig = Configuration.getClientConfig(clientName, serviceFile, deviceFile, clientVerbose)
        clientConfigs[clientName] = clientConfig
        clientDeviceConfig = Configuration.getDeviceConfig(clientName, deviceFile, clientVerbose)
        clientDeviceConfigs[clientName] = clientDeviceConfig
        q = multiprocessing.Queue()
        queues.append(q)
        clientQueues[clientName] = q

    

    for attackerName in attackerList:
        attackerConfig = Configuration.getClientConfig(attackerName, serviceFile, deviceFile, attackerVerbose)
        attackerConfigs[attackerName] = attackerConfig
        attackerDeviceConfig = Configuration.getDeviceConfig(attackerName, deviceFile, attackerVerbose)
        clientDeviceConfigs[attackerName] = attackerDeviceConfig


    # prepare Writer that is generating the SOMEIP Packets
    writerQueue = multiprocessing.Queue()
    writer = multiprocessing.Process(target=writer, args=(writerQueue, len(serverList), attackerList, attackerQueue, serverDeviceConfigs, clientDeviceConfigs, interface, pcap))
    writer.start()

    # prepare Stop Worker to shutdown all services
    clientStopQueue = multiprocessing.Queue()
    clientStop = multiprocessing.Process(target=stop, args=(clientStopQueue, len(clientList), serverList, serverQueues, ))
    clientStop.start()
    
    serverStopQueue = multiprocessing.Queue()
    serverStop = multiprocessing.Process(target=stop2, args=(serverStopQueue, len(serverList), attackerList, attackerQueue, ))
    serverStop.start() 

    # start server worker
    for serverName in serverList:
        s = Server.Server(config=serverConfigs[serverName], q=serverQueues[serverName], writer=writerQueue, clientQueues=clientQueues, attackers=attackerQueue, stopQueue=serverStopQueue,   verbose=serverVerbose)
        serverObjects[serverName] = s
        p = multiprocessing.Process(name=serverName, target=Server.server, args=(s, ))
        servers.append(p)
        p.start()


    # start client worker
    for clientName in clientList:
        c = Client.Client(config=clientConfigs[clientName], q=clientQueues[clientName], writer=writerQueue, serverQueues=serverQueues, stopQueue=clientStopQueue, counter=packetCount, attackers=attackerQueue, verbose=clientVerbose)
        clientObjects[clientName] = c
        p = multiprocessing.Process(name=clientName, target=Client.client, args=(c, ))
        clients.append(p)
        p.start()

    # start attacker
    for attackerName in attackerList:
        a = Attacker.Attacker(config=attackerConfigs[attackerName], clientConfigs=clientConfigs, clientQueues=clientQueues, serverConfigs=serverConfigs, serverQueues=serverQueues, writer=writerQueue, counter=packetCountAttack, attacks=attacks, attackerQueue=attackerQueue, attackers=attackerList, verbose=attackerVerbose)
        p = multiprocessing.Process(name=attackerName, target=Attacker.attacker, args=(a, ))
        attackers.append(p)
        p.start()


