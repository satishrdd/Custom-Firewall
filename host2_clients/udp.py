import socket
import time
s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("192.168.114.176",5556))						#bind to the socket
print time.time()
count=0
avg=0
while True:
	r,addr = s.recvfrom(5000)							#try to receive 
	print r
	t = time.time()
	if count>1:
		avg  = avg + t - prev	
	print "%.20f" % time.time()	
	count=count+1	
	prev=t
	print "Aveg is %.20f",avg/count					#find the avg time