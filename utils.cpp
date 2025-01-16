#include "utils.h"
#include "chat.h"

int send_all(int sockfd, const char *buf, size_t len)
{
  size_t total = 0;
  while (total < len)
  {
    ssize_t sent = send(sockfd, buf + total, len - total, 0);
    if (sent == -1)
    {
      return -1;
    }
    //std::cerr << "Sent: " << buf << "[" << total << ", " << total << "+" <<
    //sent << "]" << std::endl;
    total += sent;
  }
  // std::cerr << "[send] Sent done" << std::endl;
  return 0;
}

int recv_all(int sockfd, char *buf, size_t len)
{
  size_t total = 0;
  while (total < len)
  {
    ssize_t received = recv(sockfd, buf + total, len - total,
                            0); // will not block when gracefully closed
    if (received == -1)
    {
      return -1;
    }
    //std::cerr << "Recv: " << buf << "[" << total << ", " << total << "+" <<
    //received << "]" << std::endl;
    total += received;
  }
  // std::cerr << "[recv] Recv finished with " << total << " bytes" << std::endl;
  return 0;
}

void send_file_in_chunks(int sockfd, FILE *file, std::string pubkey)
{
  printf("Public key:\n %s\n", pubkey.c_str());
  std::cerr << "Sending file in chunks to " << sockfd << std::endl;
  fseek(file, 0, SEEK_END);
  size_t file_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  FileMessage msg;
  char buffer[CHUNK_SIZE];

  std::string enc_file;
  size_t chunk_cnt = 0;

  while (file_size > 0)
  {
    chunk_cnt++;
    size_t to_read = file_size > CHUNK_SIZE ? CHUNK_SIZE : file_size;
    if (to_read < CHUNK_SIZE)
    {
      memset(buffer, 0, CHUNK_SIZE);
    }
    size_t bytes_read = 0;
    while (bytes_read < to_read)
    {
      size_t read = fread(buffer + bytes_read, 1, to_read - bytes_read, file);
      if (read == 0)
      {
        break;
      }
      bytes_read += read;
    }

    std::string encrypted = encrypt_with_public_key(pubkey, std::string(buffer, CHUNK_SIZE));
    memcpy(msg.Message, encrypted.data(), ENC_CHUNK_SIZE);
    file_size -= to_read;
    msg.type = (file_size == 0);

    send_all(sockfd, (char *)&msg, sizeof(FileMessage));
    std::cerr << "Sent " << to_read << " bytes, chunk " << chunk_cnt << std::endl;
    std::cerr << "File size left: " << file_size << std::endl;
  }
  std::cerr << "File sent" << std::endl;
}

void recv_file_in_chunks(int sockfd, std::string filepath, std::string priv_key)
{
  FileMessage msg;
  filepath = "./" + filepath;
  FILE *file = fopen(filepath.c_str(), "wb");
  if (file == NULL)
  {
    perror("fopen");
    return;
  }
  std::string decrypted;
  std::string enc_chunk;
  size_t chunk_cnt = 0;

  while (1) {
    chunk_cnt++;
    recv_all(sockfd, (char *)&msg, sizeof(FileMessage));
    enc_chunk.assign(msg.Message, ENC_CHUNK_SIZE);
    enc_chunk.resize(ENC_CHUNK_SIZE);
    decrypted = decrypt_with_private_key(priv_key, enc_chunk);
    // printf("Decrypted: %s\n", decrypted.c_str());
    fwrite(decrypted.c_str(), 1, decrypted.size(), file);
    if (msg.type == 1) // all recv
    {
      break;
    }
    std::cerr << "Received " << decrypted.size() << " bytes, chunk " << chunk_cnt << std::endl;
  }
  fclose(file);
  std::cerr << "File received and saved to " << filepath << std::endl;
}


void read_message(char *buf, size_t buf_len)
{
  if (fgets(buf, buf_len, stdin) != NULL)
  {
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
    {
      buf[len - 1] = '\0';
    }
  }
}

void generate_key_pair(std::string& public_key, std::string& private_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) {
        perror("Error creating context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        perror("Error initializing keygen");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        perror("Error setting keygen bits");
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        perror("Error generating key");
    }

    // Save public key
    BIO* bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_public, pkey);
    char* public_key_data = nullptr;
    long public_key_len = BIO_get_mem_data(bio_public, &public_key_data);
    public_key.assign(public_key_data, public_key_len);

    // Save private key
    BIO* bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    char* private_key_data = nullptr;
    long private_key_len = BIO_get_mem_data(bio_private, &private_key_data);
    private_key.assign(private_key_data, private_key_len);

    // Cleanup
    BIO_free(bio_public);
    BIO_free(bio_private);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

    // Encrypt data with the public key
std::string encrypt_with_public_key(const std::string& public_key, const std::string& plaintext) {
    BIO* bio = BIO_new_mem_buf(public_key.data(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        throw std::runtime_error("Error reading public key: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error creating context: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error initializing encryption: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error determining buffer size: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    std::string ciphertext(outlen, '\0');
    if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error encrypting: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return ciphertext;
}

    // Decrypt data with the private key
std::string decrypt_with_private_key(const std::string& private_key, const std::string& ciphertext) {
    BIO* bio = BIO_new_mem_buf(private_key.data(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        throw std::runtime_error("Error reading private key: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error creating context: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error initializing decryption: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error determining buffer size: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    std::string plaintext(outlen, '\0');
    if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &outlen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        throw std::runtime_error("Error decrypting: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    plaintext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return plaintext;
}