#We use two functions for cracking passwords using a dictionary attack.
#Tries to crack hashed passwords (SHA-256 or bcrypt) using a wordlist.
import hashlib, bcrypt

def crack_sha256(hash_to_crack, wordlist_path):  #using a dictionary of possible passwords.
    with open(wordlist_path, "r") as f:
        for word in f:
            word = word.strip() #Removes newline(\n) and extra spaces from the word.
            #first - computes its SHA-256 hash using..
            #second - converts the hash to a hexadecimal string using..
            #third - compares the result with hash_to_crack.
            if hashlib.sha256(word.encode()).hexdigest() == hash_to_crack:
                return word  #return the original word (i.e., the cracked password).
    return None  #If no password matches the hash, return None.
        


def crack_bcrypt(hash_to_crack, wordlist_path):  #using a wordlist.
    with open(wordlist_path, "r") as f:
        for word in f:
            #Strips whitespace and encodes the word as bytes (bcrypt requires bytes).
            word = word.strip().encode()
            #Uses bcrypt.checkpw() to check if the password matches the hashed value.
            if bcrypt.checkpw(word, hash_to_crack.encode()):
                return word.decode()
    return None
