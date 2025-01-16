#include "tpool.h"
#include "utils.h"
#include "chat.h"
#include <sys/stat.h> 
#include <dirent.h>
#include <opencv4/opencv2/opencv.hpp>

std::string server_pub_key, server_priv_key;

struct User {
  char username[BUFFER_SIZE];
  char password[BUFFER_SIZE];
  bool isReserved;
};
std::vector<User> users_db = {{"Server", "", true}, {"q", "", true}, {"r", "", true}, {"ss", "123", false}, {"da", "123", false}};

// mutex for global mailbox
pthread_mutex_t mailbox_mutex = PTHREAD_MUTEX_INITIALIZER;
std::vector<ChatMessage> mailbox;

class ActiveUser {
public:
  User current_user, reg_user;
  int fd, tid;
  enum { NEW, REGISTER, REGISTER_FIN, LOGIN, LOGIN_FIN, LOGGED, CHAT, FILE } state;
  ActiveUser(int fd, std::string pubkey) : fd(fd), state(NEW) {
    rsa_pub_key = pubkey;
    current_user.username[0] = '\0';
    reg_user.username[0] = '\0';
    reg_user.isReserved = false;
  }
  std::string rsa_pub_key;
  // friend void process_client(std::vector<ActiveUser>::iterator user); // in
  // order to access private members
  // Use mutex to protect user-wise mailbox
};
std::vector<ActiveUser> active_users;

// map from state to menu content

const char *menu_content[] = {
    "Welcome to the chat server!\n========================\n Options:\n (1) Register\n (2) Login\n (3) See all online user\n (4) Exit\n========================\nChoice (1-4): ",
    "======= Register =======\nEnter username: ",
    "Enter password: ",
    "======= Login =======\nEnter username: ",
    "Enter password: ",
    "========================\n Options:\n (1) Chat\n (2) File Service\n (3) Logout\n (4) Logout & Exit\n========================\nChoice (1-4): ",
    "======================= Chat =======================\n",
    "======================= File Service =======================\n"
};

ThreadPool *pool = new ThreadPool(10);

int sockfd;

void sigint_handler(int signum) {
  std::cerr << "Caught signal " << signum << std::endl;
  delete pool;
  close(sockfd);
  exit(0);
}

void user_leave(std::vector<ActiveUser>::iterator user) {
  ChatMessage leave_msg;
  leave_msg.type = -1;
  snprintf(leave_msg.Message, BUFFER_SIZE, "Goodbye");
  std::cerr << "User at fd " << user->fd << " with state " << user->state
            << " left\n";
  send_all(user->fd, (char *)&leave_msg, sizeof(leave_msg));
  close(user->fd);
  active_users.erase(user);
}

void process_client(int index) {
  // Get iterator at index i
  std::cerr << "Processing client at index " << index << std::endl;
  std::vector<ActiveUser>::iterator user = active_users.begin() + index;
  user->tid = gettid();
  std::cerr << "Thread " << user->tid << " started for fd " << user->fd
            << std::endl;

  ChatMessage to_client_msg;
  ChatMessage from_client_msg;
  to_client_msg.type = 1;
  snprintf(to_client_msg.Message, BUFFER_SIZE, menu_content[ActiveUser::NEW]);
  std::cerr << "Sending welcome message to fd " << user->fd << std::endl;
  send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));

  while (recv_all(user->fd, (char *)&from_client_msg, sizeof(ChatMessage)) != -1) {
    std::vector<ActiveUser>::iterator user = active_users.begin() + index;
    for (auto it = active_users.begin(); it != active_users.end(); it++) {
      std::cerr << it->fd << std::endl;
    }
    std::cerr << "Received: " << from_client_msg.Message << " from fd " << user->fd << std::endl;
    std::cerr << "State: " << user->state << std::endl
              << "Active users: " << std::endl;
    for (const ActiveUser &u : active_users) {
      std::cerr << u.fd << " " << u.state << " " << u.current_user.username
                << std::endl;
    }
    
    if ((user->state == ActiveUser::NEW || user->state == ActiveUser::LOGGED) &&
        from_client_msg.Message[0] == '4') {
      user_leave(user);
      return;
    } // user left

    switch (user->state) {
      case ActiveUser::NEW: {
        if (from_client_msg.Message[0] == '1') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, menu_content[ActiveUser::REGISTER]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          user->state = ActiveUser::REGISTER;
        } else if (from_client_msg.Message[0] == '2') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, menu_content[ActiveUser::LOGIN]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          user->state = ActiveUser::LOGIN;
        } else if (from_client_msg.Message[0] == '3') {
          // list all online user
          std::string online_users = "Online users:\n";
          for (const ActiveUser &u : active_users) {
            if (u.current_user.username[0] != '\0' && u.current_user.isReserved == false) {
              online_users += "+ ";
              online_users += u.current_user.username;
              online_users += "\n";
            }
          }
          snprintf(to_client_msg.Message, BUFFER_SIZE, "%s%s", online_users.c_str(), menu_content[ActiveUser::NEW]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        } else if (from_client_msg.Message[0] != '4') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, "Invalid choice\n%s", menu_content[ActiveUser::NEW]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        }
        break;
      }
      case ActiveUser::REGISTER: {
        // Remove trailing newline
        strncpy(user->reg_user.username, from_client_msg.Message, BUFFER_SIZE);
        snprintf(to_client_msg.Message, BUFFER_SIZE, "Enter password: ");
        send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        user->state = ActiveUser::REGISTER_FIN;
        break;
      }
      case ActiveUser::REGISTER_FIN: {
        strncpy(user->reg_user.password, from_client_msg.Message, BUFFER_SIZE);
        if (user->reg_user.username[0] == '\0' ||
            user->reg_user.password[0] == '\0') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, "Error: Username or password cannot be empty\n%s", menu_content[ActiveUser::REGISTER]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          user->state = ActiveUser::NEW;
        } else {
          bool exists = false;
          for (const User &u : users_db) {
            if (u.isReserved == false && strcmp(u.username, user->reg_user.username) == 0) {
              exists = true;
              break;
            }
          }
          if (exists) {
            snprintf(to_client_msg.Message, BUFFER_SIZE, "Error: Username already exists\n%s", menu_content[ActiveUser::NEW]);
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            user->state = ActiveUser::NEW;
          } else {
            users_db.push_back(user->reg_user);
            snprintf(to_client_msg.Message, BUFFER_SIZE, "Registration successful! Welcome, %s!\n%s", user->reg_user.username, menu_content[ActiveUser::NEW]);
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            user->state = ActiveUser::NEW;
          }
        }
        break;
      }
      case ActiveUser::LOGIN: {
        strncpy(user->reg_user.username, from_client_msg.Message, BUFFER_SIZE);
        snprintf(to_client_msg.Message, BUFFER_SIZE, "Enter password: ");
        send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        user->state = ActiveUser::LOGIN_FIN;
        break;
      }
      case ActiveUser::LOGIN_FIN: {
        strncpy(user->reg_user.password, from_client_msg.Message, BUFFER_SIZE);
        bool exists = false;
        for (const User &u : users_db) {
          if (u.isReserved == false &&
              strcmp(u.username, user->reg_user.username) == 0 &&
              strcmp(u.password, user->reg_user.password) == 0) {
            exists = true;
            break;
          }
        } // check if user exists
        if (exists) {
          bool logged_in = false;
          for (const ActiveUser &u : active_users) {
            if (strcmp(u.current_user.username, user->reg_user.username) == 0) {
              snprintf(to_client_msg.Message, BUFFER_SIZE, "Error: User already logged in\n%s", menu_content[ActiveUser::NEW]);
              send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
              user->state = ActiveUser::NEW;
              logged_in = true;
              break;
            }
          } // check if user already logged in
          if (!logged_in) {
            snprintf(to_client_msg.Message, BUFFER_SIZE, "Login successful! Welcome, %s!\n%s", user->reg_user.username, menu_content[ActiveUser::LOGGED]);
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            user->current_user = user->reg_user;
            user->state = ActiveUser::LOGGED;
          }
        } else {
          snprintf(to_client_msg.Message, BUFFER_SIZE, "Error: Invalid username or password\n%s", menu_content[ActiveUser::NEW]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          user->state = ActiveUser::NEW;
        }
        break;
      }
      case ActiveUser::LOGGED: {
        std::cerr << "Logged choice: " << from_client_msg.Message << std::endl;
        if (from_client_msg.Message[0] == '1') {
          user->state = ActiveUser::CHAT;        
          to_client_msg.type = 0;
          snprintf(to_client_msg.Message, BUFFER_SIZE, menu_content[ActiveUser::CHAT]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        } else if (from_client_msg.Message[0] == '2') {
          user->state = ActiveUser::FILE;
          to_client_msg.type = 2;
          snprintf(to_client_msg.Message, BUFFER_SIZE, menu_content[ActiveUser::FILE]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        } else if (from_client_msg.Message[0] == '3') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, "Logged out from user %s\n%s", user->current_user.username, menu_content[ActiveUser::NEW]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          user->current_user.username[0] = '\0';
          user->state = ActiveUser::NEW;
        } else if (from_client_msg.Message[0] != '4') {
          snprintf(to_client_msg.Message, BUFFER_SIZE, "Invalid choice\n%s", menu_content[ActiveUser::LOGGED]);
          send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
        }
        break;
      }
      case ActiveUser::CHAT: {
        do {
          // attempt to get mutex 
          if (from_client_msg.type == -1) {
            // user wants to leave chat
            user->state = ActiveUser::LOGGED;
            to_client_msg.type = 1;
            snprintf(to_client_msg.Message, BUFFER_SIZE, "Leaving chat from user %s\n%s", user->current_user.username, menu_content[ActiveUser::LOGGED]);
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            // clean all messages to user
            pthread_mutex_lock(&mailbox_mutex);
            for (auto it = mailbox.begin(); it != mailbox.end(); it++) {
              if (strcmp(it->ToUser, user->current_user.username) == 0) {
                mailbox.erase(it);
              }
            }
            pthread_mutex_unlock(&mailbox_mutex);
            break;
          } else if (from_client_msg.type == 0) {
            // user wants to send message
            // retrieve user input
            std::string target_rsa_pub_key;
            if (from_client_msg.ToUser[0] == '\0' || from_client_msg.Message[0] == '\0') {
              snprintf(to_client_msg.Message, BUFFER_SIZE, "[Error] Username or message cannot be empty\n");
              snprintf(to_client_msg.ToUser, BUFFER_SIZE, "Server");
              to_client_msg.type = 0;
              send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            } else {
              bool exists = false;
              for (const ActiveUser &u : active_users) {
                if (strcmp(u.current_user.username, from_client_msg.ToUser) == 0) {
                  exists = true;
                  target_rsa_pub_key = u.rsa_pub_key;
                  break;
                }
              }
              if (!exists) {
                snprintf(to_client_msg.Message, BUFFER_SIZE, "[Error] User %s does not exist or isn't online\n", from_client_msg.ToUser);
                to_client_msg.type = 0;
                send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
              } else {
                to_client_msg.type = 1; // user-found
                strncpy(to_client_msg.Message, target_rsa_pub_key.c_str(), BUFFER_SIZE);
                send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));

                // receive encrypted message
                recv_all(user->fd, (char *)&from_client_msg, sizeof(ChatMessage));
                strncpy(from_client_msg.FromUser, user->current_user.username, BUFFER_SIZE);
                // successfully received message
                std::cerr << "Received message from " << from_client_msg.FromUser <<
                " to " << from_client_msg.ToUser << ": " << from_client_msg.Message << std::endl;

                // send message to target user
                pthread_mutex_lock(&mailbox_mutex);
                mailbox.push_back(from_client_msg);
                pthread_mutex_unlock(&mailbox_mutex);
              }
            }
          } else if (from_client_msg.type == 1) {
            std::cerr << "Retrieving messages for user " << user->current_user.username << std::endl;
            std::vector<int> msg_index;
            pthread_mutex_lock(&mailbox_mutex);
            for (auto it = mailbox.begin(); it != mailbox.end(); it++) {
              if (strcmp(it->ToUser, user->current_user.username) == 0) {
                msg_index.push_back(it - mailbox.begin());
              }
            }
            to_client_msg.msg_count = msg_index.size();
            std::cerr << "Message count: " << to_client_msg.msg_count << std::endl;
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            for (int i : msg_index) {
              std::cerr << "Sending message " << mailbox[i].Message << " to " << user->current_user.username << std::endl;
              send_all(user->fd, (char *)&mailbox[i], sizeof(ChatMessage));
              mailbox.erase(mailbox.begin() + i);
            }
            pthread_mutex_unlock(&mailbox_mutex);
          }         
        } while (recv_all(user->fd, (char *)&from_client_msg, sizeof(ChatMessage)) != -1);
        break;
      }
      case ActiveUser::FILE: {
        do {
          std::cerr << "File choice: " << from_client_msg.type << std::endl;
          if (from_client_msg.type == -1) {
            // user wants to leave file service
            user->state = ActiveUser::LOGGED;
            to_client_msg.type = 1;
            snprintf(to_client_msg.Message, BUFFER_SIZE, "Leaving file service from user %s\n%s", user->current_user.username, menu_content[ActiveUser::LOGGED]);
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            break;
          } else if (from_client_msg.type == 0) {
            // user wants to send file
            // retrieve user input
            std::cerr << "Received save path: " << from_client_msg.Message << std::endl;
            recv_file_in_chunks(user->fd, "files/" + std::string(from_client_msg.Message), server_priv_key);

          } else if (from_client_msg.type == 1) {
            // user wants to retrieve file
            // check if file exists
            std::string file_path = "files/";
            file_path += from_client_msg.Message;
            std::cerr << "Search for File path: " << file_path << std::endl;
            FILE *file = fopen(file_path.c_str(), "rb");
            std::cerr << "File: " << file << std::endl;
            if (file == NULL) {
              snprintf(to_client_msg.Message, BUFFER_SIZE, "File %s not found\n", from_client_msg.Message);
              to_client_msg.type = 0;
              send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
            } else {
              // send file in chunks of CHUNK_SIZE
              snprintf(to_client_msg.Message, BUFFER_SIZE, "File found, Downloading file %s\n", from_client_msg.Message);
              to_client_msg.type = 1;
              send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
              send_file_in_chunks(user->fd, file, user->rsa_pub_key);
            }
          } else if (from_client_msg.type == 2) {
            // user wants to list files
            // list all files under ./files
            std::string files = "Files:\n";
            DIR *dir;
            struct dirent *ent;
            if ((dir = opendir("files")) != NULL) {
              while ((ent = readdir(dir)) != NULL) {
                files += "+ ";
                files += ent->d_name;
                files += "\n";
              }
              closedir(dir);
            } else {
              perror("opendir");
            }
            snprintf(to_client_msg.Message, BUFFER_SIZE, "%s", files.c_str());
            send_all(user->fd, (char *)&to_client_msg, sizeof(ChatMessage));
          } else if (from_client_msg.type == 3) {
            // user wants to play video or audio
            std::string file_path = "files/";
            file_path += from_client_msg.Message;
            // check if file exists
            
          }
        } while (recv_all(user->fd, (char *)&from_client_msg, sizeof(ChatMessage)) != -1);
      }
    }
  }
  return;
}

int main(int argc, char *argv[]) {

  signal(SIGINT, sigint_handler);
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    return 1;
  }

  int port = atoi(argv[1]);
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(sockfd);
    return 1;
  }
  std::cerr << "Bound to port " << port << std::endl;

  if (listen(sockfd, 10) <
      0) { // 10 is the maximum number of pending connections
    perror("listen");
    close(sockfd);
    return 1;
  }
  std::cerr << "Listening on port " << port << std::endl;

  int connfd;

  generate_key_pair(server_pub_key, server_priv_key);

  printf("Server public key:\n %s\n", server_pub_key.c_str());

  // create files directory if not exists
  if (mkdir("files", 0777) == -1) {
    if (errno != EEXIST) {
      perror("mkdir");
      close(sockfd);
      return 1;
    }
  }

  while (1) {
    // Polling
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    // std::cerr << "Activity: " << activity << std::endl;
    if (activity < 0) {
      perror("select");
      close(sockfd);
      return 1;
    }

    if (FD_ISSET(sockfd, &readfds)) {
      std::cerr << "New connection\n";
      if ((connfd = accept(sockfd, NULL, NULL)) < 0) {
        perror("accept");
        close(sockfd);
        return 1;
      } else {
        std::cerr << "Accepted connection on fd " << connfd << std::endl;
        // Get client-generated pubkey
        ChatMessage pubkey_msg;
        recv_all(connfd, (char *)&pubkey_msg, sizeof(ChatMessage));
        std::string client_pub_key(pubkey_msg.Message);
        snprintf(pubkey_msg.Message, BUFFER_SIZE, "%s", server_pub_key.c_str());
        send_all(connfd, (char *)&pubkey_msg, sizeof(ChatMessage));

        active_users.emplace_back(connfd, client_pub_key); // == push_back(ActiveUser(connfd))
        // pool->add_task(std::bind(process_client, active_users.end() - 1)); //
        // wrap process_client(it) to std::function

        pool->add_task(std::bind(process_client, (int)active_users.size() - 1));
      }
    }
  }

  return 0;
}
