## Compilation 
To compile both of server and client, simply run `make` under the `code/` directory.
To recompile, run `make clean` first then `make` again.

## Usage guide
After `make`, run server on a specified port with `./server <port>`.
Client can connect to server with `./client <IP> <port>`, when server is on the same machine, run `./client 127.0.0.1 <port>`.

## Client usage
Before login, the client have three choices: Register, Login and Exit. Select the corresponding choice by typing the number and press enter. To register, you need to specify the username and a password for this username. After registration is done, you can login by typing in the same username and provide the same password. Login will only success given the correct credentials are provided, and such user exists, and the user is not logged in somewhere else.

After login, client can either enter the chat, use file service, Logout or Logout & Exit.

### Chat 
In chat, client can send messages to all other online users. 
To send a message, simply type in their name and then the message. To exit chat, type in `q` and press enter.
The server will notice the user if the user is not online or does not exist.
After each message, the server will send the pending messages to the user. Client can also check the pending messages by typing `r` and press enter.

### File service
In file service, client can upload, download and list files in the server or in the client's local directory.
To list all available commands, type `h` and press enter, a list of commands like below will be shown:
```
Commands:
1. put <filepath> <target_path> - send <filepath> to server at <target_path>
2. get <target_path> <filepath> - retrieve <target_path> from server to <filepath> locally
3. ls - list all files on server
4. ll - list all files locally
5. q - leave file service
```
For `put` and `get`, the `filepath` and `target_path` should be supplied after typing the command. 
Client program will query the user for the file path.

