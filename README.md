# Chatter

`Chatter` ensures end-to-end encrypted messaging between two users.

**Usage**
---
```
Usage: python Chatter.py
    
    End-to-end encrypted messaging system
    Developed by Tanner Smith (Github: mello9494)
```

**Built with**
-
+ `curses` - This library is used to manipulate the terminal, allowing a user to provide input while displaying
output simultaneously.
+ `threading` - This library allows a program to be split into multiple processes, for example, taking input while
output at the same time.
+ `socket` - Allows for low-level network connections.
+ `cryptography` - The cryptography library is a powerful library that includes multiple forms of encryption
and decryption.


**Requirements**
- 
+ Chatter requires the Cryptography library to run properly.
    ### Linux, macOS, and Windows
  + `pip install cryptography`


**Installation options**
-
+ Download the .zip file

**How to use**
-
1. Ensure that your machine can accept incoming traffic from port 6006.
2. Run `python Chatter.py`.
3. Select whether you would like to be open for connections or search for a connection.
    + If you selected to be open for connections, wait for a user to connect to you.
    + If you selected to search for an open connection, enter the IP of the user you would like to connect to.
4. Upon successful connection, start messaging.
5. To exit, enter "exit" to quit the program.