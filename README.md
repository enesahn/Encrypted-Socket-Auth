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
