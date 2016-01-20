"""
Bundle of methods to read the configuration Files.
"""

import xml.etree.ElementTree as ET
import SomeIPPacket

def getDeviceConfig(name, deviceFile, verbose):
    """
    Extracts the device information from the configuration file, this includes MAC, IP and Ports for all devices (server and client)
    """
    tree = ET.parse(deviceFile)
    root = tree.getroot()

    config = {}

    for dev in root.iter('device'):
        if (dev.get('name') == name):
            config['mac'] = dev.get('mac')
            config['ip'] = dev.get('ip')
            config['sendPort'] = int(dev.get('sendPort'))
            config['recPort'] = int(dev.get('recPort'))

    if verbose:
        print ('Device Config (',name,') :',config)

    return config

def str2bool(s):
    if s == 'True' or s == 'true':
        return True
    else:
        return False

def getClientConfig(name, serviceFile, deviceFile, verbose):
    """
    Extracts the meta information from the configuration file for clients, this includes clientID, services and methods allowed to request, servers providing those services and methods, information about time sentitiveness of notifications and resend intervals
    """
    tree = ET.parse(serviceFile)
    root = tree.getroot()

    config = {}

    config['clientID'] = int(getOwnID(name, deviceFile))

    services = []

    for serv in root.iter('service'):
        # client is capable of service
        if (serv.find("./method/client[@id='"+str(name)+"']") != None) :
            # service description
            service = {}
            service['id'] = int(serv.get('id'),0)
            
            # servers providing service
            servers = []
            for server in serv.iter('server'):
                servers.append(server.get('id'))
            service['server'] = servers

            # find methods suitable for client
            methods = []
            for method in serv.iter('method'):
                if (method.find("./client[@id='"+str(name)+"']") != None) :
                    methodSpec = {}
                    methodSpec['id'] = int(method.get('id'),0)
                    methodSpec['type'] = SomeIPPacket.messageTypes[method.get('type')]
                    
                    minValue = 1
                    maxValue = 10
                    resendMin = 1
                    resendMax = 5
                    timesensitive = False

                    # go through all clients specifying this method
                    for curClient in method.iter('client'):
                        # only one match here
                        if curClient.get('id') == name:
                            
                            if curClient.get('min') != None:
                                minValue = float(curClient.get('min'))
                            if curClient.get('max') != None:
                                maxValue = float(curClient.get('max'))
                            interval = (minValue, maxValue)

                            if curClient.get('timesensitive') != None:
                                timesensitive = str2bool(curClient.get('timesensitive'))


                            if curClient.get('resendMin') != None:
                                resendMin = float(curClient.get('resendMin'))
                            if curClient.get('resendMax') != None:
                                resendMax = float(curClient.get('resendMax'))

                    methodSpec['resendMin'] = resendMin
                    methodSpec['resendMax'] = resendMax
                    methodSpec['interval'] = interval
                    methodSpec['timesensitive'] = timesensitive
                    methods.append(methodSpec)
            service['method'] = methods

            services.append(service)
            

    config['service'] = services

    if verbose:
        print ('Client Config (',name,') :',config)

    return config

def getServerConfig(name, serviceFile, verbose):
    """
    Extracts the meta information from the configuration file for servers, this includes provided services and methods, error rates and response intervals
    """
    tree = ET.parse(serviceFile)
    root = tree.getroot()

    config = {}

    for serv in root.iter('service'):
        if (serv.find("./servers/server[@id='"+str(name)+"']") != None) :
            methods = []
            for method in serv.iter('method'):
                methodSpec = {}
                methodSpec['id'] = int(method.get('id'),0)
                methodSpec['type'] = SomeIPPacket.messageTypes[method.get('type')]
                methods.append(methodSpec)
            config[int(serv.get('id'),0)] = {}
            config[int(serv.get('id'),0)]['methods'] = methods
            for curServer in serv.iter('server'):
                if curServer.get('id') == name:
                    config[int(serv.get('id'),0)]['errorRate'] = float(curServer.get('errorRate'))
                    config[int(serv.get('id'),0)]['min'] = int(curServer.get('min'))
                    config[int(serv.get('id'),0)]['max'] = int(curServer.get('max'))
            
    if verbose:
        print ('Server Config (',name,') :',config)

    return config

def getOwnID(name, configFile):
    tree = ET.parse(configFile)
    root = tree.getroot()

    for dev in root.iter('device'):
        if (dev.get('name') == name):
            return dev.get("clientID")

