#include "utils.h"
#include "chat.h"
#include <csignal>
#include <cassert>
#include <dirent.h>

char buffer[BUFFER_SIZE];

int sockfd;

void sigint_handler(int signum)
{
  // std::cerr << "Caught signal " << signum << std::endl;
  // inform server
  snprintf(buffer, BUFFER_SIZE, "Goodbye");
  close(sockfd);
  exit(0);
}

int main(int argc, char *argv[])
{

  // Connect to the server
  signal(SIGINT, sigint_handler);
  if (argc != 3)
  {
    perror("Usage: ./client <server_ip> <port>");
    return 1;
  }

  struct sockaddr_in serv_addr;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("Socket creation failed");
    return 1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(strtol(argv[2], NULL, 10));

  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
  {
    perror("Address not supported");
    return 1;
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    perror("Connection failed");
    return 1;
  }

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(sockfd, &readfds);

  ChatMessage msg;
  std::string pub_key, priv_key, tmp, server_pub_key;

  generate_key_pair(pub_key, priv_key);
  strcpy(msg.Message, pub_key.c_str());
  send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
  recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));
  server_pub_key = std::string(msg.Message);
  printf("Server public key:\n %s\n", server_pub_key.c_str());
  //printf("Public key:\n %s\n", pub_key.c_str());

  while (1)
  {
    if (select(sockfd + 1, &readfds, NULL, NULL, NULL) < 0)
    {
      perror("Select failed");
      return 1;
    }
    if (FD_ISSET(sockfd, &readfds))
    {
      recv_all(sockfd, (char*)&msg, sizeof(ChatMessage));
      //printf("Message details: %d %d %s %s %s\n", msg.type, msg.msg_count, 
      //        msg.FromUser, msg.ToUser, msg.Message);
      if (msg.type == -1) {
        printf("%s\n", msg.Message);
        close(sockfd);
        return 0;
      } else if (msg.type == 0) {
        printf("%s", msg.Message);
        while (1) {
          // retrieve 
          msg.type = 1;
          send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
          recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));
          if (msg.msg_count == 0) {
            printf("No new messages\n");
          } else {
            printf("You have %d new messages\n", msg.msg_count);
          }
          int to_read = msg.msg_count;
          for (int i = 0; i < to_read; i++)
          {
            recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            tmp.resize(msg.msg_len);
            tmp.assign(msg.Message, msg.msg_len);
            std::string decrypted = decrypt_with_private_key(priv_key, tmp);
            printf("<%s> %s\n", msg.FromUser, decrypted.c_str());
          }

          // send
          std::string to_user;
          msg.type = 0;
          printf("To (maximum=20, type \"q\" to leave, r to read message): ");
          scanf("%s", msg.ToUser);
          to_user = std::string(msg.ToUser);

          int c;
          while ((c = getchar()) != '\n' && c != EOF);

          if (strcmp(msg.ToUser, "q") == 0) {
            msg.type = -1;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            break;
          } else if (strcmp(msg.ToUser, "r") == 0) {
            continue;
          }
          send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
          recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));

          if (msg.type == 0) {
            printf("%s\n", msg.Message); // user not found
          } else {
            // get their key
            std::string their_pub_key_str = std::string(msg.Message);

            printf("Message (maximum=1024): ");
            read_message(msg.Message, BUFFER_SIZE);

            tmp.assign(msg.Message);
            std::string encrypted = encrypt_with_public_key(their_pub_key_str, tmp);
            memcpy(msg.Message, encrypted.data(), BUFFER_SIZE);
            msg.msg_len = encrypted.size();
            strncpy(msg.ToUser, to_user.c_str(), BUFFER_SIZE);
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
          }              
        }
      } else if (msg.type == 1) {
        printf("%s", msg.Message);
        scanf("%s", msg.Message);
        send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
      } else if (msg.type == 2) {
        // file service
        printf("%s", msg.Message);
        printf("Welcome to file service, type h for help\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        while (1) {
          printf("> ");
          scanf("%s", msg.Message);
          if (strcmp(msg.Message, "h") == 0) {
            printf("Commands:\n");
            printf("1. put <filepath> <target_path> - send <filepath> to server at <target_path>\n");
            printf("2. get <target_path> <filepath> - retrieve <target_path> from server to <filepath> locally\n");
            printf("3. ls - list all files on server\n");
            printf("4. ll - list all files locally\n");
            printf("5. play <filename> - play audio/video file at server\n");
            printf("6. q - leave file service\n");
          } else if (strcmp(msg.Message, "q") == 0) {
            msg.type = -1;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            break;
          } else if (strncmp(msg.Message, "get", 3) == 0) {
            std::string filepath;
            while ((c = getchar()) != '\n' && c != EOF);
            printf("target_path (maximum=1024)> ");
            read_message(msg.Message, BUFFER_SIZE);
            printf("filepath (empty for same name)> ");
            read_message(buffer, BUFFER_SIZE);
            if (strlen(buffer) == 0) {
              filepath = std::string(msg.Message);
            } else {
              filepath = std::string(buffer);
            }
            // std::cerr << "Filepath: " << filepath << ", Target path: " << msg.Message << std::endl;
            msg.type = 1;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));

            if (msg.type == 0) {
              // file not found
              printf("%s", msg.Message);
            } else {
              printf("%s", msg.Message);
              recv_file_in_chunks(sockfd, filepath, priv_key);
            }

          } else if (strncmp(msg.Message, "put", 3) == 0) {

            while ((c = getchar()) != '\n' && c != EOF);
            printf("filepath (maximum=1024)> ");
            read_message(buffer, BUFFER_SIZE);
            printf("target_path (empty for same name)> ");
            msg.Message[0] = '\0';
            read_message(msg.Message, BUFFER_SIZE);
            if (strlen(msg.Message) == 0) {
              strncpy(msg.Message, buffer, BUFFER_SIZE);
            }
          
            msg.type = 0;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));

            // check if file locally
            FILE* file = fopen(buffer, "r");
            if (file == NULL) {
              printf("File %s not found\n", buffer);
            } else {
              send_file_in_chunks(sockfd, file, server_pub_key);
            }
            
          } else if (strcmp(msg.Message, "ls") == 0) {
            msg.type = 2;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            recv_all(sockfd, (char *)&msg, sizeof(ChatMessage));
            printf("%s", msg.Message);
          } else if (strcmp(msg.Message, "ll") == 0) {

            DIR *dir;
            struct dirent *ent;
            if ((dir = opendir(".")) != NULL) {
              printf("Files:\n");
              while ((ent = readdir(dir)) != NULL) {
                printf("+ %s\n", ent->d_name);
              }
              closedir(dir);
            } else {
              perror("opendir");
            }
          } else if (strncmp(msg.Message, "play", 4) == 0) {
            while ((c = getchar()) != '\n' && c != EOF);
            printf("filename (maximum=1024)> ");
            read_message(msg.Message, BUFFER_SIZE);
            msg.type = 3;
            send_all(sockfd, (char *)&msg, sizeof(ChatMessage));
          } else {
            printf("Invalid command\n");
          }
        }
      }
    }
  }
}

