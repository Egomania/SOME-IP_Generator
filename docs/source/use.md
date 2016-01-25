# Usage

## Basics

python start.py

Note that the trace is out out-of-order, you can use e.g. reordercap to cope with this.

## config.ini

The main configuration file is located in src/config.ini.

``` ini
[Files]
deviceFile=config/devices.xml
serviceFile=config/services.xml

[Pcap]
file=traces/temp.pcap
interface=lo
counter=50

[Attacks]
counter=10
min=1
max=3
attacks=fakeClientID, wrongInterface, disturbTiming, fakeResponse, sendErrorOnError, sendErrorOnEvent, deleteRequest, deleteResponse

[Verbose]
client=false
server=false
attacker=false
```

The *Files* section lists the additionally needed meta data file.
 * **deviceFile** contains information like name, type, mac, ip, sender port and receiving port
 * **serviceFile** contains information about offered and requested services

The *Pcap* section defines needed information for the ouput.
 * **file** describes the location where to store the resulting pcap
 * **interface** describes the interface the packets are sent to
 * **counter** defines the number of packets generated per client (Note that in case more sending options are given to a client the resulting packets generated will be duplicated)

The *Attacks* section defines all needed information for the attacker configuration.
 * **counter** defines the rate an attack will be performed, if this is set to zero non attack will be performed.
 * **min** defines the minimum response time of the attacker in ms
 * **max** defines the maximum response time of the attacker in ms
 * **attacks** defines which attacks can be used, note that every module located in src/attacks/ is possible

The *Verbose* sections defines whether or not additional information is printed for a dedicated component.

## devices.xml

The file to define device information is located at src/devices.xml. 
A device config looks as follows:

``` xml
<device name="SomeIPServer0x1000" type="server" mac="02:1A:AA:AA:AA:AA" ip="10.0.0.1" sendPort="30491" recPort="30491" />
```

The following information can be specified:
 * **Name** of the device
 * **type** of the device (server, client or attacker)
 * **mac** Address of the device
 * **ip** Address of the device
 * **sendPort** as Port from which messages are sent
 * **recPort** as Port from which messages are received

Client have an additional attribute *clientID*.

Note that the system needs at least one attacker as this component acts as a MitM and forwards messages to the original entities.
If an attack-free dump is needed configure an attck count of 0 ind the config.ini file.

## services.xml

The file to define service information is located at src/services.xml.
A service entry look as follows:

``` xml
<service id="0x1000">
	<!-- Methods -->
	<method id="0x0111" type="REQUEST" >
		<client id="SomeIPClient0x3020" timesensitive="false" min="1" max="10" resendMin="2" resendMax="3" />
		<client id="SomeIPClient0xC010" timesensitive="true" min="4.9" max="5.1" resendMin="2" resendMax="3" />
	</method>
	<!-- Devices -->
	<servers>
		<server id="SomeIPServer0x1000" errorRate="0.1" min="1" max="5"/>
	</servers>	
</service>
```

First, the *id* of the service is defined.
Note that this id corresponds to the id appaering in the SOME/IP Packet.

Second, the methods associated with the service are specified.
This contains the *method id* and the *message type*.
The *message type* can be REQUEST, REQUEST_NO_RETURN or NOTIFICATION.
The clients allowed to use those methods are listed afterwards.
The *client* information compasses of
 * **id** that has to be the same as in devices.xml
 * **timesensitive** that defines whether or not messages are sent on a regular basis
 * **min** defines the minimum interleave between packets of the same configuration
 * **max** defines the maximum interleave between packets of the same configuration
 * **min** defines the minimum interleave between resending a packet after an error
 * **max** defines the maximum interleave between resending a packet after an error

The last part is defining the servers offering the services.
The *server* information compasses of
 * **id** that has to be the same as in devices.xml
 * **errorRate** probability that the request is not answered with a response
 * **min** defines the minimum response time 
 * **max** defines the maximum response time 

