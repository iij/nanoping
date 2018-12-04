# nanoping

"nanoping" is a high time accuracy ping program that relies on hardware time stamping function on ethernet controller hardwares.
The nanoping enables pricise packet timestamping at NIC phy/mac layer, therfore it is no delay and jitter by software process.

Timestamp resolution and precision is defined by the hardware oscillator on ethernet controller.
For example, minimum timestamping resolution is 12.5ns on the Intel X550 ethernet controller, because it has 80MHz oscillator for the timestamping function.

## Requirements
- Linux 4.x kernel (We tested on Ubuntu 18.04LTS)
- [latest ixgbe driver](https://sourceforge.net/projects/e1000/files/ixgbe%20stable/) (We tested ixgbe 5.3.7 and 5.5.2)
- NIC with Intel ethernet controller
  - Recommended NIC: X550 series ethernet controller (X550 PCIe NIC or X553 on Intel SoC)
  - Supported NIC (with some limitations): i210, i350, i82599, X520, X540, XL710
  - Alternatively, another NIC which has hardware timestamp function with Linux device driver is probably able to use the nanoping.

## How to build

- run ```make``` command on the nanoping source directory.
- run ```make install```

## How to use

nanoping is client and server type application.
You have to setup the server mode nanoping on the target server before start client mode nanoping.
After server side nanoping is ready, user can start client side nanoping.
Root privilege is required to execute the nanoping.

Following is a typical example of nanoping setting.

On server host:

```
$ nanoping --server --interface <network interface>
```
On client host:

```
$ nanoping  --client --interface <network interface> --delay 1000000 <IP address of server host>
```

The client-side nanoping outputs the results as traditional ping-like result.

```
$ sudo nanoping --client --interface eno0 --count 5 --delay 100 192.168.0.1
nanoping 192.168.0.1:10666...
192.168.0.1: seq=1 time=268ns
192.168.0.1: seq=2 time=268ns
192.168.0.1: seq=3 time=269ns
<snip>
192.168.0.1: seq=26971 time=256ns
192.168.0.1: seq=26972 time=262ns
192.168.0.1: seq=26973 time=262ns
--- nanoping statistics ---
26976 packets transmitted, 26975 received, 0.003707% packet loss, time 5.429561 s
26975 RX stamp collected, 26976 TX stamp collected
RX: found 26973 previous RX stamp, found 26973 previous TX timestamp
TX: found 0 previous RX stamp, found 0 previous TX stamping
TX: TX stamp too late 0
26973 Remote RX stamp collected, 26973 Remote TX stamp collected
26973 delta_t calcurated
SWD min/avg/max = 249/261/275 ns
```
### Command line options

The same nanoping binary can work as both of server and client.
Two modes have different command line options as below.

#### server side
```
server: nanoping --server --interface [nic] --port [port] --emulation
--ptpmode --silent --timeout [usec] --busypoll [usec] --dummy-pkt [cnt]
```

- ```--server```:  server mode.
- ```--interface [nic]```(or ```-i```): specify NIC name to bind the server socket.
- ```--port [port]```(or ```-p```): (optional) specify the port number to bind the server socket. default port: 10666.
- ```--emulation```(or ```-e```): (optional) emulate hardware timestamping function. With the option, nanoping will work on any ethernet controller that has no PTP/hardware timestamp function. However time precision is almost same as normal ping application.
- ```--ptpmode```(or ```-P```): (optional) camouflage ping-pong probe packets as PTP packet. Some ethernet controller has strict filtering for timestamp target packet only for PTP protocol, this option is effective for suck kind of NICs (for example Intel XL710).
- ```--silent```(or ```-s```): (optional) suppress output to the console.
- ```--timeout [usec]```(or ```-t```): (optional) specify timeout threshold of ping transaction.
- ```--busypoll [usec]```(or ```-b```): (optional) set ```SO_BUSY_POLL``` socket option for ping-pong socket (see detail socket(7))
- ```--dummy-pkt [cnt]```(or ```-x```): (optional) send additional [cnt] packets during each ping-pong transaction.  This option produces broader bandwidth for the measurements stream.

#### client side

```
client: nanoping --client --interface [nic] --count [sec] --delay [usec]
--port [port] --log [log] --emulation --ptpmode --silent
--timeout [usec] --busypoll [usec] --dummy-pkt [cnt] [host]
```

- ```--client```: client mode.
- - ```--interface [nic]```(or ```-i```): specify NIC name to send/recv ping-pong packets.
- ```--count [sec]```(or ```-n```): (optional) duration of nanoping measurement. default: 0 = for ever.
- ```--delay [usec]```(or ```-d```): (optional) interval of each ping packets. default: 100usec
- ```--port [port]```(or ```-p```): (optional) specify port number of server side process. default port: 10666
- ```--log [log]```(or ```-l```): (optional) if a filename was given, detail log will be recoreded to the file.
- ```--emulation```(or ```-e```): (optional) enable emaulation of hardware timestaping function.
- ```--ptpmode```(or ```-P```): (optional) camouflage ping-poing probe packets as PTP packet.
- ```--silent```(or ```-s```): (optional) suppress output to the console.
- ```--timeout [usec]```(or ```-t```): (optional) specify timeout threshold of ping transaction. default: 5000000usec(=5sec)
- ```--busypoll [usec]```(or ```-b```): (optional) set ```SO_BUSY_POLL``` socket option for ping-pong socket (see detail socket(7))
- ```--dummy_pkt [cnt]```(or ```-x```): (optional) send additional [cnt] packets during each ping-pong transaction. This option enables broader bandwidth for the measurement stream.

## Time stamp points

```
        client          server
          |    ping       |
        t0|-------------->|t1
          |               |
          |    pong       |
        t3|<--------------|t2
          |               |
          v               v
```

Each ping-pong transaction has 4 timestamps, and these are enough to calculate RTT (Round Trip Time) between client and server. RTT is calculated by ((t3-t0) - (t2-t1))/2.

## Accuracy of nanoping timestamps

Nanoping uses timestamp function in a ethernet controller hardware.
Hardware timestamp is driven oscillator on the ethernet controller, threrfore the accuracy of the nanoping measurement depends on the acuracy of it.

For example, Intel X550 ethernet controller has 80MHz oscillator for the time stamp hardware (*1). The resolution is a 12.5ns tick. Nanoping can record all timestamps in the accuracy.
However, each individual internal oscillator has its unique characteristics,
Usually, a little clock difference exists in some PPMs (up to 50ppm).
So without external reference clock to calibrate the internal oscillator, the clock diffrence between client and server ethernet controllers generate some errors to prevent enough accurate OWD (one-way dealy) calucuration.

(*1) [Intel Ethernet controller X550 Datasheet](https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/ethernet-x550-datasheet.pdf)  7.7 Time SYNC (IEEE1588 and 802.1AS)


## Log file format

With the ```--log``` option, nanoping records all packet timestamp.

```
seq,stat,t0,t1,t2,t3,t3-t0,t2-t1,sum,delta_t,num_txs
2,ok,1541667306.439213316,1541667289.936457336,1541667289.936648473,1541667306.455477441,0.016264125,0.000191137,0.016072988,0.008036494,0
3,ok,1541667306.479411253,1541667289.976654473,1541667289.976845561,1541667306.495676028,0.016264775,0.000191088,0.016073687,0.008036843,0
4,ok,1541667306.519617941,1541667290.016862798,1541667290.017053523,1541667306.535884953,0.016267012,0.000190725,0.016076287,0.008038143,0
5,ok,1541667306.559821753,1541667290.057067098,1541667290.057258598,1541667306.576086553,0.016264800,0.000191500,0.016073300,0.008036650,0
6,ok,1541667306.600030153,1541667290.097274811,1541667290.097461248,1541667306.616290553,0.016260400,0.000186437,0.016073963,0.008036981,0
7,ok,1541667306.640261566,1541667290.137505873,1541667290.137697973,1541667306.656527566,0.016266000,0.000192100,0.016073900,0.008036950,0
8,ok,1541667306.680469216,1541667290.177714611,1541667290.177904523,1541667306.696738903,0.016269687,0.000189912,0.016079775,0.008039887,0
9,ok,1541667306.720678691,1541667290.217923186,1541667290.218114036,1541667306.736946166,0.016267475,0.000190850,0.016076625,0.008038312,0
10,ok,1541667306.760887441,1541667290.258132511,1541667290.258323798,1541667306.777152741,0.016265300,0.000191287,0.016074013,0.008037006,0
11,ok,1541667306.801080578,1541667290.298324298,1541667290.298513748,1541667306.817348741,0.016268163,0.000189450,0.016078713,0.008039356,0
<snip>
```

Each line in the log file shows one ping-pong transaction. From the left column,

- Sequence #
- transaction status.
- t0: ping sent time at the client.
- t1: ping recieved time at the server.
- t2: pong sent time at the server.
- t3: pong received time at the client.
- t3-t0: time delta between ping sent and pong received at the client side.
- t2-t1: time delta between ping received and pong sent at the server side.
- sum: (t3-t0)-(t2-t1) (RTT)
- delta_t: RTT/2
- num_txs: debug information, ignore it.
