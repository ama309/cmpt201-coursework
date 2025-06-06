#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// tokenize function
int tokenize(char *buffer, char *delimiter) {
  // get first token and see if exit character
  char *saveptr;
  char *token = strtok_r(buffer, delimiter, &saveptr);
  if (strcmp(token, "\n") == 0) {
    return -1;
  }

  // print the tokens
  printf("Tokens:");
  while (token != NULL) {
    printf("\n  %s", token);
    token = strtok_r(NULL, delimiter, &saveptr);
  }
  return 1;
}

// main loop
int main() {
  // declare variables
  char *buffer;
  size_t size;
  ssize_t line;
  int exit = 1;

  // loop until exit character
  while (exit != -1) {
    printf("Please enter some text: ");
    buffer = NULL;
    size = 0;
    line = getline(&buffer, &size, stdin);

    // if some error, free memory and exit, else tokenize
    if (line != -1) {
      exit = tokenize(buffer, " ");
    } else {
      exit = -1;
    }
    free(buffer);
  }
  return 0;
}

// Optional1: Works fine with spaces but tab counts as new character, so it is
// added in the tokens
// Optional2: Done
// Optional3: Done
