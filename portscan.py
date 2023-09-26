import socket
from IPy import IP

def scan(target):
	converted_ip = check_ip(target)
	get_time = input("[+] Set time for each scan (more time more accurate) or Skip: ")
	print("---{}---".format(target))
	total_open = 0
	for port in range(0,ports + 1):
		total_open += scan_port(check_ip(target),port,get_time)
	print("---Total Opened Ports Found: {}---\n".format(total_open))

def check_ip(ip):
	try:
		IP(ip)
		return ip
	except ValueError:
		return socket.gethostbyname(ip)

def get_banner(s):
	return s.recv(1024)

def scan_port(ip_address,port,time_scan):
	open_ports = 0
	try:
		sock = socket.socket()
		try:
			sock.settimeout(int(time_scan))
		except:
			sock.settimeout(0.1)
		sock.connect((ip_address,port))
		open_ports += 1
		try:
			banner = get_banner(sock)			
			print("[+] Connection Established On Port: {} = Version:{}".format(port,banner.decode().strip("\n")))
		except:
			print("[+] Connection Established On Port: {}".format(port))
	except:
		pass
	return open_ports
targets = input("[+] Enter Target/s to scan (split multiple targets with ,): ")
ports = int(input("[+] Enter Port Range you desire to scan: "))


if "," in targets:
	for target in targets.split(","):
		scan(target.strip(" "))
else:
	scan(targets)
