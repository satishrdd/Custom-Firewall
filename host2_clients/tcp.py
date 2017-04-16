import socket
from thread import *
import time

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("192.168.114.176",5556))						#bind with ip and port
s.listen(5)
print time.time()
count=0
avg=0
while True:
	conn,addr = s.accept()
	r = conn.recvfrom(5000)								#try to receive packet
	print r[0]
	t = time.time()
	if count>1:
		avg  = avg + t - prev	
	print "%.20f" % time.time()	
	count=count+1	
	prev=t
	print "Aveg is %.20f",avg/count							#find avg time
	#s.close()
	#break
