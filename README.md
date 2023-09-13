# Encrypted Socket Auth
Private AES256 Socket Auth System

# Client
I used CryptoPP for encryption. It generates the IV key randomly and sends it to the server. 
Values sent to the server;
Key (encrypted)
HWID (encrypted)
Version ( encrypted )
IV key (unencrypted)

# Server
The server decrypts the incoming encrypted values with the unencrypted IV key and sends the values to the KeyAuth API. And sends a response to the client and discord webhook according to the response.

# Credits
https://github.com/KeyAuth-Archive/serverside-keyauth

# Alternative
We take the AES-256 key , iv and session id randomly and save them to the mysql table. The client sends the session id to the server, the server connects to mysql and gets the key and iv from the column with session id and decrypts the encrypted data. In this way, it is more secure.
