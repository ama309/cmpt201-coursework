#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\e[9;31m"
#define GRN "\e[0;32m"
#define CRESET "\e[0m"

#define handle_error(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

size_t read_all_bytes(const char *filename, void *buffer, size_t buffer_size) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    handle_error("Error opening file");
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size > buffer_size) {
    handle_error("File size is too large");
  }

  if (fread(buffer, 1, file_size, file) != file_size) {
    handle_error("Error reading file");
  }

  fclose(file);
  return file_size;
}

void print_file(const char *filename, const char *color) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    handle_error("Error opening file");
  }

  printf("%s", color);
  char line[256];
  while (fgets(line, sizeof(line), file)) {
    printf("%s", line);
  }
  fclose(file);
  printf(CRESET);
}

int verify(const char *message_path, const char *sign_path, EVP_PKEY *pubkey);

int main() {
  // File paths
  const char *message_files[] = {"message1.txt", "message2.txt",
                                 "message3.txt"};
  const char *signature_files[] = {"signature1.sig", "signature2.sig",
                                   "signature3.sig"};

  // TODO: Load the public key using PEM_read_PUBKEY
  EVP_PKEY *pubkey = NULL;
  // first open public_key.pem as FILE
  FILE *pubkey_file = fopen("public_key.pem", "r");
  if (!pubkey_file) {
    fprintf(stderr, "File opening error.\n");
  }
  // then load the public key
  pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
  fclose(pubkey_file);
  if (!pubkey) {
    fprintf(stderr, "Load key error.\n");
  }

  // Verify each message
  for (int i = 0; i < 3; i++) {
    printf("... Verifying message %d ...\n", i + 1);
    int result = verify(message_files[i], signature_files[i], pubkey);

    if (result < 0) {
      printf("Unknown authenticity of message %d\n", i + 1);
      print_file(message_files[i], CRESET);
    } else if (result == 0) {
      printf("Do not trust message %d!\n", i + 1);
      print_file(message_files[i], RED);
    } else {
      printf("Message %d is authentic!\n", i + 1);
      print_file(message_files[i], GRN);
    }
  }

  EVP_PKEY_free(pubkey);

  return 0;
}

/*
    Verify that the file `message_path` matches the signature `sign_path`
    using `pubkey`.
    Returns:
         1: Message matches signature
         0: Signature did not verify successfully
        -1: Message is does not match signature
*/
int verify(const char *message_path, const char *sign_path, EVP_PKEY *pubkey) {
#define MAX_FILE_SIZE 512
  unsigned char message[MAX_FILE_SIZE];
  unsigned char signature[MAX_FILE_SIZE];

  // TODO: Check if the message is authentic using the signature.
  // Look at: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

  // step 1
  FILE *msg_file = fopen(message_path, "r");
  if (!msg_file) {
    fprintf(stderr, "File read error.\n");
    return 0;
  }
  size_t msg_len = fread(message, 1, MAX_FILE_SIZE, msg_file);
  fclose(msg_file);
  if (ferror(msg_file)) {
    fprintf(stderr, "File read error.\n");
    return 0;
  }
  // step 2
  FILE *sign_file = fopen(sign_path, "r");
  if (!sign_file) {
    fprintf(stderr, "File read error.\n");
    return 0;
  }
  size_t sig_len = fread(signature, 1, MAX_FILE_SIZE, sign_file);
  fclose(sign_file);
  if (ferror(sign_file)) {
    fprintf(stderr, "File read error.\n");
    return 0;
  }
  // step 3
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fprintf(stderr, "ctx error.\n");
    return 0;
  }
  // step 4
  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey)) {
    fprintf(stderr, "Verify error.\n");
    EVP_MD_CTX_free(ctx);
    return 0;
  }
  if (EVP_DigestVerifyUpdate(ctx, message, msg_len)) {
    fprintf(stderr, "Verify error.\n");
    EVP_MD_CTX_free(ctx);
    return 0;
  }
  int val = EVP_DigestVerifyFinal(ctx, signature, sig_len);
  // step 5
  EVP_MD_CTX_free(ctx);
  if (val == 1) {
    return 1;
  } else {
    return -1;
  }
}
