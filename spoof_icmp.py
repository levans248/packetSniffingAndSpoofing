#!/usr/bin/python3

from scapy.all import *

a = IP()
a.dst = '10.0.2.4' # target vm
a.src = '1.1.1.1' # uncomment this line to spoof the source of our icpm packet
b = ICMP()
p = a / b
send(p)

