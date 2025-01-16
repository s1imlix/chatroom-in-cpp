#ifndef CHAT_H
#define CHAT_H

#include <string>
#include "utils.h"

struct ChatMessage {
    int type;
    int msg_count;
    size_t msg_len;
    char FromUser[BUFFER_SIZE];
    char ToUser[BUFFER_SIZE];
    char Message[BUFFER_SIZE];
};

struct FileMessage {
    int type;
    char Message[ENC_CHUNK_SIZE];
};

#endif // CHAT_H