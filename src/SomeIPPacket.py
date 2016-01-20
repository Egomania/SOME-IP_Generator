""" Module for SOME/IP Packet. Includes classes and functions that manage operating with SOME/IP Packets. """

import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

#SERVICE TYPES
serviceTypes = {    'SERVICE_TYPE_PA' : 0x1000,
                    'SERVICE_TYPE_CA' : 0x2000,
                    'SERVICE_TYPE_PSU' : 0x3000,
                    'SERVICE_TYPE_CCVS' : 0x3010,
                    'SERVICE_TYPE_SNA' : 0x3020,
                    'SERVICE_TYPE_RLA' : 0x5000,
                    'SERVICE_TYPE_PAX' : 0x6000,
                    'SERVICE_TYPE_SA' : 0xC000,
                    'SERVICE_TYPE_CCVSA' : 0xC010}


#ERROR CODES
errorCodes = {  'E_OK' : 0x00,
                'E_NOT_OK' : 0x01,
                'E_UNKNOWN_SERVICE' : 0x02,
                'E_UNKNOWN_METHOD' : 0x03,
                'E_NOT_READY' : 0x04,
                'E_NOT_REACHABLE' : 0x05,
                'E_TIMEOUT' : 0x06,
                'E_WRONG_PROTOCOL_VERSION' : 0x07,
                'E_WRONG_INTERFACE_VERSION' : 0x08,
                'E_MALFORMED_MESSAGE' : 0x09,
                'E_WRONG_MESSAGE_TYPE' : 0x0a}

#MESSAGE TYPE
messageTypes = {    'REQUEST' : 0x00,
                    'REQUEST_NO_RETURN' : 0x01,
                    'NOTIFICATION' : 0x02,
                    'RESPONSE' : 0x80,
                    'ERROR' : 0x81}

#METAINFO
VERSION = 0x01
INTERFACE = 0x01

class SomeIP(Packet):
    """ Given a Packet, the SOME/IP Header information is parsed and a new Header is added. """

    global VERSION
    global INTERFACE

    name = "SOMEIP"
    fields_desc = [ XShortField("ServiceID", None),
                    XShortField("MethodID", None),
                    FieldLenField("Length", None, length_of="Payload", adjust=lambda pkt,x: x+8, fmt="I"),
                    XShortField("ClientID", None),
                    XShortField("SessionID", None),
                    XByteField("ProtocolVersion", VERSION),
                    XByteField("InterfaceVersion", INTERFACE),
                    XByteField("MessageType", None),
                    XByteField("ReturnCode", None),
		            StrLenField("Payload", "", length_from=lambda pkt:pkt.Length)]


def createPayload():
    """ Creat arbitrary payload ranging from 0 to 20 Byte. """
    alpha = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F")
    length = random.randint(0,20)
    payload = ''.join([random.choice(alpha) for _ in range(length)])
    return payload


def createSomeIP(SenderConfig, ReceiverConfig, MsgConfig):
    """ 
    Create a SomeIP packet based on IP/UDP 
    
    :param SenderConfig: Needed for MAC, IP and Port information of the sender.    
    :param ReceiverConfig: Needed for MAC, IP and Port information of the receiver.    
    :param MsgConfig: Content of the SOME/IP Packet incl. Header and payload.
    :returns: a SOME/IP Packet over IP/UDP    
    """    

    srcMAC = SenderConfig['mac']
    dstMAC = ReceiverConfig['mac']

    srcIP = SenderConfig['ip']
    dstIP = ReceiverConfig['ip']

    srcPort = SenderConfig['port']
    dstPort = ReceiverConfig['port']

    pl = createPayload()

    service = MsgConfig['service']
    method = MsgConfig['method']
    client = MsgConfig['client'] 
    session = MsgConfig['session'] 
    msgtype = MsgConfig['type']
    ret = MsgConfig['ret']
    proto = MsgConfig['proto']
    iface = MsgConfig['iface']

    
    packet = Ether(src=srcMAC, dst=dstMAC)/IP(src=srcIP, dst=dstIP)/UDP(dport=dstPort, sport=srcPort)/SomeIP(ServiceID=service, MethodID=method, ClientID=client, SessionID=session, MessageType=msgtype, ReturnCode=ret, Payload=pl, ProtocolVersion=proto, InterfaceVersion=iface)

    return packet

