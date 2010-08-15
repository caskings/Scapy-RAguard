#!/usr/bin/python

"""
Copyright 2010 (c) Craig Askings <craig@askings.com.au>
Licensed under the terms of the GNU GPL License version 3


This script listens for rogue IPv6 Router Advertisments.

"""
from scapy.all import *


sniff(filter="icmp6", store =0,  prn=lambda x: x.show())
