#Finds subdomains of a website by checking names from a wordlist.
import requests #Used for making HTTP request.
import socket #It is used for DNS into IP addresses.

def enumerate_subdomain(domain, wordlist_path):
    found = []  #Initializes an empty list.
    with open(wordlist_path, "r") as f:
        for line in f :    #Iterates over each line
            subdomain = f"{line.strip()}.{domain}" #concatenates the main domain to from a full subsomain
            #The try-except block handles errors that occur when a subdomain cannot be resolved to an IP.
            #Without it, the program would crash when it encounters a subdomain that doesn’t exist.
            #With it, the code skips bad subdomains and continues processing the rest.
            try:
                ip = socket.gethostbyname(subdomain)
                found.append((subdomain, ip))
            #If DNS resolution fails (socket.gaierror), the code ignores the error and continues to the next line.
            except socket.gaierror:
                continue
    return found
