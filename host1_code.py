import socket
from thread import *                                    #required libraries
import struct
import time


try:
	#creating a raw scoket and binding it to card interface
	s_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(0x0800))
	interface="enp3s0f1"
	s_raw.bind((interface,socket.ntohs(0x0800)))
	src_mac = [0x08,0x00,0x27,0x72,0x6c,0xa9,0xb8,0x2a,0x72,0xcb,0x71,0x04,0x08,0x00]      #mac adresses of firewall and host1
	payload = "".join(map(chr,src_mac))
        s2 = "192.168.0.2"
        #s = bytes('192.168.0.1', 'utf-8')
        #s = "192.168.114.176"
        s = raw_input("Enter Desination IP")            #take input the ip of host2
        l=[]
        temp = ""
        for i in range(0,len(s)):
                if s[i]=='.':
                        l.append(int(temp))
                        temp=""
                else:
                        temp = temp+s[i]
                        if i==len(s)-1:
                                l.append(int(temp))
        #s2 = str.encode(s2)
        print s2
        #for tcp header
        srcport = 5568
        #dstport = 5556
        dstport = int(raw_input("Enter destination port"))      #take input port of destination
        syn=0
        ack=0
        fl = int(raw_input("Enter 6 for tcp ,17 for udp or 1 for icmp"))        #take input type of traffic
	head = struct.pack('!HHIIHHHH',4,fl,20,20,l[0],l[1],l[2],l[3])
	t = struct.pack('!HHLL',srcport,dstport,syn,ack)               #create headers accordingly
        u= struct.pack('!HHHH',srcport,dstport,0,0)
        i = struct.pack('!BBH',9,0,1000)
        for k in range (0,10000):
                s_raw.send(payload+head+t+"hello world")               #send the packet on raw socket
	print "messafe sent"
except Exception as e:
	print e 
	print "error"                                  #if error print it

