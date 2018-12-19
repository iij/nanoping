# systemd template for nanoping server

This is sample systemd template for nanoping server.

## how to use it.

- edit the nanoping location in the template file to fit your environment
- install the systemd template file to ```/etc/systemd/system/```
- enable the template by ```systemd enable nanopingd@<interface name>```
  if you have multiple interfaces to bind the nanoping server, repeat that for all interfaces.
