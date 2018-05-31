import socket
import sys
import os
import netifaces as ni
import re

ipList=[]
targetList=[]
vulCheck="n"
filename=str()
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
		print ""
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
		if vulCheck == "y":
			banner = s.recv(1024)
			if not len(banner) == 0:
				return banner
			else:
				return str(s)
		else:
			return str(s)

	except socket.error:
		return 0

def check(banner, filename):
	f.open(filename,'r')
	for line in f.readlines():
		if line.strip() == banner:
			return True 
def finish():
	if vulCheck == "y":
		serverList=[]
		for banner in targetList:		
			if check(banner,filename) == True:
				serverList.append(banner)
				print""
				print "[+] " + str(len(targetList)) + " targets found."
	else:
		if (len(ipList) == 0):
			print ""
			print "[-] No devices with open ports found. "
		else: 
			print ""
			for ipPort in ipList:
				print ipPort
			print ""
			print "[+] FOUND " + str(len(ipList)) + " devices with open ports."
			
	print "Thank you for using my porScanner."	

def main():
	print "----------------------JS PORT SCANNER---------------------"

	print "Please select interface:"
	interfaces = ni.interfaces()
	for x in range(0,len(interfaces)):
		print str(x)+") " +  interfaces[x]

	selectint=-1
	while(selectint==-1): 
		try:
			selectint = input("Number:")
		except SyntaxError:
			print "[-] Please don't leave this input empty."
		if selectint<0 or selectint>len(interfaces):
			selectint = -1

	ipP = getIp(interfaces[selectint])
	print ""
	print "Please choose the ip range:"
	print "0) all <default>"
	print "1) own range"
	try:
		rangeMode = input("Number:")
	except SyntaxError:
		rangeMode = 0

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
				print ""
			if rangeStart > rangeEnd or 1>rangeStart or rangeStart>255 or rangeEnd<1 or rangeStart>255 :
				print "[-] Invalid range. Try again"
				print ""
			else: 
				rangeError = False
	print ""
	print "Please choose the port range:"
	print "0) typical ports <default>"
	print "1) all (very slowly)"
	print "2) own single port"
	
	try:
		portRange = int(input("Number:"))
	except SyntaxError:
		portRange = 0

	if portRange == 1:
		portList=[]
		for x in range(1,65535):
			portList.append(x)
	elif portRange == 2:
		portList=[]
		while(len(portList) == 0):
			try:
				portList.append(input("PORT:"))
			except SyntaxError:
				print "[-] Please don't leave this input empty"

	else:
		portList=[21,22,25,80,110,443]
	print ""
	print "Do you like to check the targets of vulnerability?"
	try:
		vulCheck=raw_input("Yes <y> or No <n>:") 
	except SyntaxError:
		vulCheck = "n"

	if vulCheck == "y":
		filePath=str()
		while(len(filePath) == 0):
			try:
				filePath = raw_input("Please insert the path to your target list:")
			except SyntaxError:
				print "[-] Please don't leave this input empty."
				print ""	
			if not os.path.isfile(filePath):
				filePath = str() 
				print "[-] " + filePath + "does not exist. Please try again."
				print ""
		filename = filePath
	else:
		vulCheck="n"
	print "---------------------Starting portScanner--------------------"
	for ip in range (rangeStart,rangeEnd):
		for port in portList:
			sys.stdout.write('\r                                                        ')	
			sys.stdout.write('\r'  +str((round(((    float(((ip-rangeStart))  *  (len(portList))    +   (portList.index(port)+1))    /    float ((rangeEnd-rangeStart) * (len(portList)))      )),4))*100)   +'% SCAN: ' + ipP + '.' +str(ip)+':'+str(port))
			sys.stdout.flush()
			response = scan(ipP + '.' +str(ip),port)
			if response != 0:
				if vulCheck == "y":
					targetList.append((ipP + '.' +str(ip) + ':' + str(port)) + response)
				else:
					ipList.append( (ipP + '.' +str(ip) + ':' + str(port)) )

	finish()
	

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		finish()		
		exit()
	except Exception, e:
		print ""
		print "[-] Error: " + str(e)
