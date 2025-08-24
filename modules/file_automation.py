#os library is used for proform basic operation on file.
#Can rename files with a prefix or delete .tmp files in a folder.
import os 

def rename_files(directory, prefix):
    #Go through each item in the folder, numbering them (0,1,2,...)
    for count, filename in enumerate(os.listdir(directory)):
        src = os.path.join(directory, filename)   #Make the full path of the current file.
        dst = os.path.join(directory, f"{prefix}_{count}")  #Create a new file name with the prefix and number.
        os.rename(src, dst)  #remane the file.

def delete_temp_files(directory):
    for file in os.listdir(directory): #look at each file in the folder.
        if file.endswith(".tmp"):  #Check if the file ends with .tmp 
            os.remove(os.path.join(directory,file))  #Delete the file