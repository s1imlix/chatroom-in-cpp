# Makefile, compile server.cpp, client.cpp, and utils.c 

CC = g++
CFLAGS = -Wall -g 
LIBS = -lssl -lcrypto 

SERVER_EXEC = server
CLIENT_EXEC = client

# Source files
SERVER_SRCS = server.cpp utils.cpp tpool.cpp
CLIENT_SRCS = client.cpp utils.cpp

# Default target: build both server and client
all: $(SERVER_EXEC) $(CLIENT_EXEC) 

# Rule to build the server executable directly from source files
$(SERVER_EXEC): $(SERVER_SRCS)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

# Rule to build the client executable directly from source files
$(CLIENT_EXEC): $(CLIENT_SRCS)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

# also clean the object files and the executables
clean:
	rm -f server client

.PHONY: all clean
