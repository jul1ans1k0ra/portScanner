import socket
import sys
import os
import netifaces as ni
import re


targetList=[]

def getIp(interface):
	ips=[]
        fip = ni.ifaddresses(interface)
        keys = fip.keys()
       	for key in keys:
               	addr = str(fip.get(key))
               	addr =  re.findall("[0-1][0-9]+[.][0-9]+[.][0-9]+[.][0-9]+",addr)
               	for x in range(0,len(addr)):
                       	if not (addr[x]=="127.0.0.1"):
                               	ips.append(addr[x])
	if len(ips) == 0:
		print "[-] No Connection on interface:" + interface 
		exit() 
	ipc = ips[0]
	ipsc = re.findall("[0-9]+",ips[0])
	ip = str(ipsc[0]) + "." + str(ipsc[1]) + "." + str(ipsc[2])
	return ip


def scan(ip,port): 
	try:	
		s = socket.socket()
		socket.setdefaulttimeout(2)
		s.connect((ip,port))
		banner = s.recv(1024)
		return banner
	except socket.error:
		return 0
	except Exception, e:
		print "[-]Error: "+ str(e)

def check(banner, filename):
	if not os.path.isfile(filename):
		print "[-] " + filename + "does not exist."
	else: 
		f.open(filename,'r')
		for line in f.readlines():
			if line.strip() == banner:
				return True 
def finish():
	if not len(targetList) == 0:
		serverList=[]
		for banner in targetList:		
			if check(banner,filename) == True:
				serverList.append(banner)
				print ""
				print "[+] target found."
				print""
				print "[+] " + str(len(targetList)) + " targets found."
	else:
		print ""
		print "[+] No targets found. "
	print "Good Bye."	

def main():
	print "----------------------JS PORT SCANNER---------------------"

	print "Please select interface:"
	interfaces = ni.interfaces()
	for x in range(0,len(interfaces)):
		print str(x)+") " +  interfaces[x]
	selectint = input("Number:")
	ipP = getIp(interfaces[selectint])

	print "Please choose the ip range"
	print "0) all <default>"
	print "1) own range"
	rangeMode = input("Number:")
	rangeStart = 1
	rangeEnd = 255

	if rangeMode == 1:
		rangeError=True
		while(rangeError):
			try:
				rangeStart = input("Range from:")
				rangeEnd = input("Range to:")
			except SyntaxError:
				rangeStart = 0
				rangeEnd = 0
				print "[-] This input can not be empty."
			if rangeStart > rangeEnd or 1>rangeStart or rangeStart>255 or rangeEnd<1 or rangeStart>255 :
				print "[-] Invalid range. Try again"
			else: 
				rangeError = False
				
		
	portList=[21,22,25,80,110,443]
	filename=sys.argv[0] + "vuln.txt"

	for ip in range (rangeStart,rangeEnd):
		for port in portList:
			sys.stdout.write('\r                                                        ')	
			sys.stdout.write('\r'  +str((round(((    float(((ip-rangeStart))  *  (len(portList))    +   (portList.index(port)+1))    /    float ((rangeEnd-rangeStart) * (len(portList)))      )),4))*100)   +'% SCAN: ' + ipP + '.' +str(ip)+':'+str(port))
			sys.stdout.flush()
			response = scan(ipP + '.' +str(ip),port)
			if response != 0:
				targetList.append(response)

	finish()
	

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		finish()		
		exit()
