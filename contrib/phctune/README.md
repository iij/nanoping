# phctune
phctune is a utility application to calibrate PHC (PTP hardware clock) on an ethernet controller.
Precise PHC calibration requires the PTP GMC(Grand Master Clock).
However, GMC may not exist in your local environment.
phcture is useful for suck kind of situation.
It calibrates local PHC using NTP calibrated in-kernel clock.
Short term clock stability is not enough for precise PHC calibration, but long term clock stability is sufficient for the purpose in almost all cases.

## How to use

Enable NTP time synchronization on your host, and then run ```phctune --interface <interface> -sleep 10```. It takes a few minutes to extract the calibration parameter.

## Command line options

The phctune has following command line options
- ```--interface [interface]```(or ```-i```): specify the primary target PHC.
- ```--sleep [sec]``` (or ```-s```): specify interval duration between caribration trials.
- ```--subinterface [interface]```(or ```-I```): (optional) specify another interface which shares a same hardware oscillator with the primary target interface.
- ```--log [filename]````(or ```-l```): (optional) output log to a file.
