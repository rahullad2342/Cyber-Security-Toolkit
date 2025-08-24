#This code is a multi-threaded port scanner, which checks which ports are open on a given IP address.
#Scans an IP address to find open ports (used to find running services).
import socket  #Used to create connections to network ports.
import threading  #Used to run multiple port scans at the same time.

#Tries to connect to a specific port on a given IP address.
def scan_port(ip, port, result):
    s = socket.socket()  #Create A socket
    s.settimeout(0.5)  #Set timeout
    try:
        s.connect((ip, port)) #try to connect
        result.append(port) 
    except:
        pass  #If the connection fails (port closed or blocked), it’s ignored.
    finally:
        s.close()

def scan_ports(ip, ports = range(1, 1025)):
    #Initialize results and thread list.
    result = []
    threads = []
    for port in ports:
        #Create a new thread to scan that port.
        t = threading.Thread(target=scan_port, args=(ip, port, result))
        t.start()
        threads.append(t)  #add thread to list.
    for t in threads:  #Wait fir all thread to finish.
        t.join()
    return result
