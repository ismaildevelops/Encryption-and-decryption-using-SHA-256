import cryptography
from cryptography.fernet import Fernet
##Fernet uses 128 bit AES IN CBC mode.

import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


##The above mentioned modules are imported to aid us in implimenting
##the AES encryption. AES encryption is asymmetric encryption method
##in which the encrtyption key used to encrypt the data
##is the same for decrypting it.UNLIKE RSA where we have two different keys


##Since we dont want to save keys everytime inside a
##file now we will create a password.Now we can take
##either password as input or
##give it inside a variable

password = input("Enter your password. make sure it is strong enough:  ")
print("\n")
text_file = input("Enter the name of text file you want to encrypt :This text file should be\n in the same directory as your script :  ")
print("\n")


salt = b'o\x10\xce\xee\xefGE=\xc4\xfe`\xd6=\xd6\xad\xde5\x0f\xa1\xdf\xa0!\x8e[\xab'
#created using os.urandom(25)

##salts are the additional data that are used to protect the
##data which might be similar fo instance there might be a possibility
##that two users can have same passwords.Thus to safeguard it we
##use salt which works as
##SHA256(salt+password)
##Thus in this way the salted value will be different for both of the
##passwords stored and it will be computationaly difficult for the hacker to
##retrieve the password.

#password = "password" #password should not be easily guessable
password22 = password.encode() #encoding the password 

kdf = PBKDF2HMAC(   #Password-based key Derivation function 2
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password22))
print('Following is the key generated based on your password \n')

print(key)

##This will create an encryption file for key because it is not possible for everyone to remember long keys
##and because it is very crucial for decryption therefore a file is created which will have the encryption key

file = open('encrypt.enc','wb')
file.write(key)
file.close()

##The text file which will be opened for encryption all the text contained inside of this text file will be encrypted

file = open(text_file ,'rb')

data = file.read()

encoded = data

##
##a new object of Fernet class is being created 
f = Fernet(key)

encrypted = f.encrypt(encoded)
print('\n')
print('The encrypted message is as belows \n\n')
print(encrypted)
print('\n\n')
print('A new file encrypt.enc has been created\n')



key2 = input("Would you like to decrypt the encrypted message: y/n")

key2 =input("Enter the name of encryption file (It was created in the same directory where your code was executed under the name of encrypt.enc): ")

file = open('encrypt.enc','r')
key = file.read()
file.close()

f2 = Fernet(key)
print(key)
decrypted = f2.decrypt(encrypted)
print('The decrypted message is as belows \n')
print(decrypted)
k = input("\n The above message is encoded in byte types would you like to convert it into string : y/n ? ")
if (k == 'y'):
    print("\n",decrypted.decode())
else:
    print("\n THANKS FOR USING OUR PROGRAM")
    







