import socket, sys
from struct import *
from thread import *
#Convert a string of 6 characters of ethernet address into a dash separated hex string

import json

def Rule_is_Subset(rule,arr):
	#assumption this will have a tuple
	array=[]
	for i in xrange(0,len(arr)):
		if arr[i][0] == -1:
			if rule[0] < 0:
				if rule[1]<=arr[i][1]:
					return
				else:
					array.append(i)
			elif rule[0] == 0:
				if rule[1]<arr[i][1]:
					return
			elif rule[0] == 1:
				pass
			else:
				if rule[1]<=arr[i][1]:
					return
				elif rule[0]<=arr[i][1]:
					#take union of both rules
					#update the rule
					rule[0] = -1
					array.append(i)
				else:
					#do nothing
					pass
		elif arr[i][0] == 0:
			if rule[0]<0:
				if arr[i][1]<rule[1]:
					array.append(i)
			if rule[0] == 0:
				if rule[1] == arr[i][1]:
					return
			if rule[0] == 1:
				if rule[1]<arr[i][1]:
					array.append(i)
			if rule[0] >1 :
				if rule[1]>arr[i][1] and rule[0]<arr[i][1]:
					array.append(i)
		elif arr[i][0] == 1:
			if rule[0]<0:
				pass
			elif rule[0] == 0:
				if rule[1]>arr[i][1]:
					return
			elif rule[0] == 1:
				if rule[1]>arr[i][1]:
					return
				elif rule[1] == arr[i][1]:
					return
				else:
					array.append(i)
			else:
				if rule[0] >= arr[i][1]:
					return
				elif rule[1] > arr[i][1]:
					array.append(i)
					rule[0] = 1
					rule[1] = rule[0]
		else:
			if rule[0]<0:
				if arr[i][1]<=rule[1]:
					array.append(i)
				elif arr[i][0]<=rule[1]:
					array.append(i)
					rule[1] = arr[i][1]
				else:
					pass
			elif rule[0] == 0:
				if arr[i][1]>rule[1] and arr[i][0]<rule[1]:
					return
			elif rule[0] == 1:
				if rule[1]<=arr[i][0]:
					array.append(i)
				elif rule[1]<=arr[i][1]:
					array.append(i)
					rule[1] = arr[i][0]
				else:
					pass
			elif rule[0] > 1:
				if rule[0]>=arr[i][0] and rule[1]<=arr[i][1]:
					return
				elif rule[0]<arr[i][1] and rule[1]>arr[i][1] and rule[0]>=arr[i][0]:
					array.append(i)
					rule[0] = arr[i][0]
				elif rule[0]<arr[i][1] and rule[1]>arr[i][1] and rule[0]<arr[i][0]:
					array.append(i)
				elif rule[0]<=arr[i][0] and rule[1]>arr[i][0] and rule[1]<=arr[i][1]:
					array.append(i)
					rule[1] = array[i][1]
				elif rule[0]<=arr[i][0] and rule[1]>arr[i][0] and rule[1]>arr[i][1]:
					array.append(i)
				else:
					pass
	array = list(set(array))
	for x in xrange(0,len(array)):
		arr.pop(array[x]-x)
	arr.append(rule)

class Ruleset(object):
	"""docstring for Ruleset"""
	data = {}
	def __init__(self, arg):
		self.data = arg
	def add(self,type,value):
		if value == 1 or value == 2 or value == 3:
			add = raw_input("enter a valid address to block:")
			if type == 1:
				if value == 1:
					self.data["Inbound"]["MAC"].append(add)
					self.data["Inbound"]["MAC"] = list(set(self.data["Inbound"]["MAC"]))
				if value == 2:
					self.data["Inbound"]["IPv4"].append(add)
					self.data["Inbound"]["IPv4"] = list(set(self.data["Inbound"]["IPv4"]))
				if value == 3:
					self.data["Inbound"]["IPv6"].append(add)
					self.data["Inbound"]["IPv6"] = list(set(self.data["Inbound"]["IPv6"]))
			else :
				if value == 1:
					self.data["Outbound"]["MAC"].append(add)
					self.data["Outbound"]["MAC"] = list(set(self.data["Outbound"]["MAC"]))
				if value == 2:
					self.data["Outbound"]["IPv4"].append(add)
					self.data["Outbound"]["IPv4"] = list(set(self.data["Outbound"]["IPv4"]))
				if value == 3:
					self.data["Outbound"]["IPv6"].append(add)
					self.data["Outbound"]["IPv6"] = list(set(self.data["Outbound"]["IPv6"]))
		elif value == 4 or value == 5 or value == 6:
			add = input("Enter a port number:")
			pre = input("Rule type 1. < , 2. = or 3.> 4. range  (equals or greater or less or as a part of range) rule?")
			pre -= 2
			if pre == 2:
				pre = input("Enter second Port:")
				add2 = pre
				pre = add
				add = add2
			if type == 1:
				if value == 4:
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["ICMP"])
					#self.data["Inbound"]["ICMP"].append((int(pre),int(add)))
					self.data["Inbound"]["ICMP"] = list(set(self.data["Inbound"]["ICMP"]))
				if value == 5:
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["TCP"])
					#self.data["Inbound"]["TCP"].append((int(pre),int(add)))
					self.data["Inbound"]["TCP"] = list(set(self.data["Inbound"]["TCP"]))
				if value == 6:
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["UDP"])
					#self.data["Inbound"]["UDP"].append((int(pre),int(add)))
					self.data["Inbound"]["UDP"]= list(set(self.data["Inbound"]["UDP"]))
			else :
				if value == 4:
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["ICMP"])
					#self.data["Outbound"]["ICMP"].append((int(pre),int(add)))
					self.data["Outbound"]["ICMP"] = list(set(self.data["Outbound"]["ICMP"]))
				if value == 5:
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["TCP"])
					#self.data["Outbound"]["TCP"].append((int(pre),int(add)))
					self.data["Outbound"]["TCP"] = list(set(self.data["Outbound"]["TCP"]))
				if value == 6:
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["UDP"])
					#self.data["Outbound"]["UDP"].append((int(pre),int(add)))
					self.data["Outbound"]["UDP"] = list(set(self.data["Outbound"]["UDP"]))

	def delete(self,type,value):
		v1,v2 = "",""
		if type == 1:
			v1 = "Inbound"
		else:
			v1 = "Outbound"
		if value == 1:
			v2 = "MAC"
		elif value == 2:
			v2 = "IPv4"
		elif value == 3:
			v2 = "IPv6"
		elif value == 4:
			v2 = "ICMP"
		elif value == 5:
			v2 = "TCP"
		else:
			v2 = "UDP"

		print "Rule Id's:"
		for x in xrange(0,len(self.data[v1][v2])):
			print x,self.data[v1][v2][x]
			pass

		id_s = input("Enter the ruleid to delete:")
		while id_s<0 or id_s>(len(self.data[v1][v2])-1):
			id_s = input("Enter the Correct ruleid to delete:")
		self.data[v1][v2].pop(id_s)
		print "deletion successfull"
		pass
	def update(self,type,value):
		v1,v2 = "",""
		if type == 1:
			v1 = "Inbound"
		else:
			v1 = "Outbound"
		if value == 1:
			v2 = "MAC"
		elif value == 2:
			v2 = "IPv4"
		elif value == 3:
			v2 = "IPv6"
		elif value == 4:
			v2 = "ICMP"
		elif value == 5:
			v2 = "TCP"
		else:
			v2 = "UDP"

		print "Rule Id's:"
		for x in xrange(0,len(self.data[v1][v2])):
			print x,self.data[v1][v2][x]
			pass

		id_s = input("Enter the ruleid to Update:")
		while id_s<0 or id_s>(len(self.data[v1][v2])-1):
			id_s = input("Enter the Correct ruleid to update:")
	
		self.data[v1][v2].pop(id_s)
		if value == 1 or value == 2 or value == 3:
			add = raw_input("enter a valid address to update:")
			if type == 1:
				if value == 1:
					self.data["Inbound"]["MAC"].append(add)
					self.data["Inbound"]["MAC"] = list(set(self.data["Inbound"]["MAC"]))
				if value == 2:
					self.data["Inbound"]["IPv4"].append(add)
					self.data["Inbound"]["IPv4"] = list(set(self.data["Inbound"]["IPv4"]))
				if value == 3:
					self.data["Inbound"]["IPv6"].append(add)
					self.data["Inbound"]["IPv6"] = list(set(self.data["Inbound"]["IPv6"]))
			else :
				if value == 1:
					self.data["Outbound"]["MAC"].append(add)
					self.data["Outbound"]["MAC"] = list(set(self.data["Outbound"]["MAC"]))
				if value == 2:
					self.data["Outbound"]["IPv4"].append(add)
					self.data["Outbound"]["IPv4"] = list(set(self.data["Outbound"]["IPv4"]))
				if value == 3:
					self.data["Outbound"]["IPv6"].append(add)
					self.data["Outbound"]["IPv6"] = list(set(self.data["Outbound"]["IPv6"]))
		elif value == 4 or value == 5 or value == 6:
			add = input("Enter a port number:")
			pre = input("Rule type 1. < , 2. = or 3.> 4. range  (equals or greater or less or as a part of range) rule?")
			pre -= 2
			if pre == 2:
				pre = input("Enter second Port:")
				add2 = pre
				pre = add
				add = add2
			if type == 1:
				if value == 4:
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["ICMP"])
					#self.data["Inbound"]["ICMP"][id_s] = (int(pre),int(add))
					self.data["Inbound"]["ICMP"] = list(set(self.data["Inbound"]["ICMP"]))
				if value == 5:
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["TCP"])
					#self.data["Inbound"]["TCP"][id_s] = (int(pre),int(add))
					self.data["Inbound"]["TCP"] = list(set(self.data["Inbound"]["TCP"]))
				if value == 6:
					#self.data["Inbound"]["UDP"][id_s] = (int(pre),int(add))
					Rule_is_Subset((int(pre),int(add)),self.data["Inbound"]["UDP"])
					self.data["Inbound"]["UDP"] = list(set(self.data["Inbound"]["UDP"]))

			else :
				if value == 4:
					#self.data["Outbound"]["ICMP"][id_s] = (int(pre),int(add))
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["ICMP"])
					self.data["Outbound"]["ICMP"] = list(set(self.data["Outbound"]["ICMP"]))
				if value == 5:
					#self.data["Outbound"]["TCP"][id_s] = (int(pre),int(add))
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["TCP"])
					self.data["Outbound"]["TCP"] = list(set(self.data["Outbound"]["TCP"]))
				if value == 6:
					#self.data["Outbound"]["UDP"][id_s] = (int(pre),int(add))
					Rule_is_Subset((int(pre),int(add)),self.data["Outbound"]["UDP"])
					self.data["Outbound"]["UDP"] = list(set(self.data["Outbound"]["UDP"]))

		print "Updation Successful"
		pass

	def stats(self):
		print(json.dumps(self.data, indent = 4))
		pass

	def verify(self,macAdd,bool_IPv4,IPv4,bool_IPv6,IPv6,bool_ICMP,ICMPPort,bool_TCP,TCPPort,bool_UDP,UDPPort,bool_Inbound,bool_outbound):
		if bool_Inbound:
			if macAdd in self.data["Inbound"]["MAC"]:
				print "Packet Rejected as MacAdd failed"
				return False
			if bool_IPv4:
				if IPv4 in self.data["Inbound"]["IPv4"]:
					print "Packet Rejected as IPv4 failed"
					return False
			if bool_IPv6:
				if IPv6 in self.data["Inbound"]["IPv6"]:
					print "Packet Rejected as IPv6 failed"
					return False
			if bool_ICMP:
				for i in range(0,len(self.data["Inbound"]["ICMP"])):
					if self.data["Inbound"]["ICMP"][i][0] == -1:
						if ICMPPort<self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					elif self.data["Inbound"]["ICMP"][i][0] == 0:
						if ICMPPort == self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					elif self.data["Inbound"]["ICMP"][i][0] == 1:
						if ICMPPort>self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					else :
						if ICMPPort>self.data["Inbound"]["ICMP"][i][0] and ICMPPort<self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
			if bool_TCP:
				for i in range(0,len(self.data["Inbound"]["TCP"])):
					if self.data["Inbound"]["TCP"][i][0] == -1:
						if TCPPort<self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					elif self.data["Inbound"]["TCP"][i][0] == 0:
						if TCPPort == self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					elif self.data["Inbound"]["TCP"][i][0] == 1:
						if TCPPort>self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					else :
						if TCPPort>self.data["Inbound"]["TCP"][i][0] and TCPPort<self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
			if bool_UDP:
				for i in range(0,len(self.data["Inbound"]["UDP"])):
					if self.data["Inbound"]["UDP"][i][0] == -1:
						if UDPPort<self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					elif self.data["Inbound"]["UDP"][i][0] == 0:
						if UDPPort == self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					elif self.data["Inbound"]["UDP"][i][0] == 1:
						if UDPPort>self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					else :
						if UDPPort>self.data["Inbound"]["UDP"][i][0] and UDPPort<self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
			return True
		if bool_outbound:
			if macAdd in self.data["Outbound"]["MAC"]:
				print "Packet Rejected as MacAdd failed"
				return False
			if bool_IPv4:
				if IPv4 in self.data["Outbound"]["IPv4"]:
					print "Packet Rejected as IPv4 failed"
					return False
			if bool_IPv6:
				if IPv6 in self.data["Outbound"]["IPv6"]:
					print "Packet Rejected as IPv6 failed"
					return False
			if bool_ICMP:
				for i in range(0,len(self.data["Outbound"]["ICMP"])):
					if self.data["Outbound"]["ICMP"][i][0] == -1:
						if ICMPPort<self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					elif self.data["Outbound"]["ICMP"][i][0] == 0:
						if ICMPPort == self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					elif self.data["Outbound"]["ICMP"][i][0] == 1:
						if ICMPPort>self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					else :
						if ICMPPort>self.data["Outbound"]["ICMP"][i][0] and ICMPPort<self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
			if bool_TCP:
				for i in range(0,len(self.data["Outbound"]["TCP"])):
					if self.data["Outbound"]["TCP"][i][0] == -1:
						if TCPPort<self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					elif self.data["Outbound"]["TCP"][i][0] == 0:
						if TCPPort == self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					elif self.data["Outbound"]["TCP"][i][0] == 1:
						if TCPPort>self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					if TCPPort>self.data["Outbound"]["TCP"][i][0] and TCPPort<self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
			if bool_UDP:
				for i in range(0,len(self.data["Outbound"]["UDP"])):
					if self.data["Outbound"]["UDP"][i][0] == -1:
						if UDPPort<self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					elif self.data["Outbound"]["UDP"][i][0] == 0:
						if UDPPort == self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					elif self.data["Outbound"]["UDP"][i][0] == 1:
						if UDPPort>self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					else :
						if UDPPort>self.data["Outbound"]["UDP"][i][0] and UDPPort<self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False

			return True
		pass

#-----this is where we rock-------#

print "Lets add some rules to the firewall just use close to start the firewall:"

myDict = {
	"Inbound":{
		"TCP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1, 999 )
		],
		"UDP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1,999)
		],
		"MAC":[
			"6c:c2:17:6s:04:c5"
		],
		"IPv4":[
			"192.168.35.5"
		],
		"IPv6":[
			"2001:db8:85a3:0:0:8a2e:370:7334"
		],
		"ICMP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(1,30000)
		]
	},
	"Outbound":{
		"TCP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1,100)
		],
		"UDP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1,200)
		],
		"MAC":[
			"6c:c2:17:6s:04:c5"
		],
		"IPv4":[
			"192.168.35.5"
		],
		"IPv6":[
			"2001:db8:85a3:0:0:8a2e:370:7334"
		],
		"ICMP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(1,30000)
		]
	}
}

mySet = Ruleset(myDict);

while 1:					#menu for changing rules
	print "Operations:"
	print "1.Add"
	print "2.delete"
	print "3.update"
	print "4.Show Stats"
	print "5.Close"
	x = input("input the id of operation:")
	if x == 1 or x == 2 or x == 3:
		rule_type = input("input rule type 1.inbound or 2.outbound (just give the id of rule):")
		in_type = input("input type(1.MAC,2.IPv4,3.IPv6,4.ICMP,5.TCP,6.UDP):")
		if x == 1:
			mySet.add(rule_type,in_type)
		if x == 2:
			mySet.delete(rule_type,in_type)
		if x == 3:
			mySet.update(rule_type,in_type)
	elif x == 4:
		mySet.stats()
	elif x== 5:
		break
	else:
		print "give correct id of operation:"


		


def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0800))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# receive a packet
dictas={}
dictlis=[]
while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print str(eth_addr(packet[6:12]))
    if str(eth_addr(packet[6:12])) != "b8:2a:72:cb:71:04":
	continue
    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
	        
	ip_header = packet[eth_length:20+eth_length]
        
        #now unpack them :)
        iph = unpack('!HHIIHHHH' , ip_header)
 	print iph					#unpack the header
 	iph_length = iph[2]
	version=iph[0]
 	ttl = iph[3]
        protocol = iph[1]
 	s_addr = (iph[4]);
        d_addr = str(iph[4])+'.'+str(iph[5])+'.'+str(iph[6])+'.'+str(iph[7]);
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
 	
	src_mac = str(eth_addr(packet[6:12]))
	
	
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+12]
 
            #now unpack them :)
            tcph = unpack('!HHLL' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            #doff_reserved = tcph[4]
            #tcph_length = doff_reserved >> 4
	    tcph_length = 12
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

            x=(src_mac,True,d_addr,False,"",False,"",True,dest_port,False,0,True,False)
            
	    if x in dictlis:
		if dictas[x]:
			print "ok acc to rules done faster"
		else:
			continue
	    elif mySet.verify(src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False):
		dictas[x]=True
		dictlis.append(x)
		print dictlis
		print "ok acc to rules"
	    else:
		dictas[x]=False
		dictlis.append(x)
		print dictlis
		continue
            h_size = eth_length + iph_length + tcph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    print d_addr
	    print dest_port
	    soc.connect((d_addr,dest_port))
	    soc.sendall(data)
	    soc.close()
            print 'Data : ' + data
 
        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	    soc.sendto(data,(d_addr,8888)) 
             
            print 'Data : ' + data
 
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
            x = (src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False)
            if x in dictlis:
		if dictas[x]:
			print "ok acc to rules done faster"
		else:
			print "checking done faster"
			continue
	    if mySet.verify(src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False):
		dictas[x]=True
		dictlis.append(x)
		print "ok acc to rules"
	    else:
		dictas[x]=False
		dictlis.append(x)
		continue
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	    soc.sendto(data,(d_addr,dest_port))
	    soc.close()
            print 'Data : ' + data
 
        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
             
        print
