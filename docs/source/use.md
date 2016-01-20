# Usage

## Basics

python src/Generator.py

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
fakeClientID=true
wrongInterface=true
disturbTiming=true
fakeResponse=true
sendErrorOnError=true
sendErrorOnEvent=true
deleteRequest=true
deleteResponse=true

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
 * The other options define whether or not a specififc attack is included

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

