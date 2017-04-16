import socket

def listen():
  s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
  s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)				#create a icmp listening socket
  while 1:
    data, addr = s.recvfrom(1508)					#receive data on this socket.
    print data
    s.close()
    break

listen()