import re
password = input("Enter string to test: ")
# Password must contain an uppercase letter, a lowercase letter, a number, 
# and have a length between 8 and 20 characters.
if re.match(r"^(?=.*[\d])(?i)(?=.*[A-Z])[\w\d@#$]{8,20}$", password):
    print ("match")
else:
    print ("Not Match")