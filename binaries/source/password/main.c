#include "stdio.h"
#include "string.h"

#define PASSWORD "password123"

int main() {
    char input[100] = {0};
    do {
        fgets(input, 100, stdin);
        input[strnlen(input, 100) - 1] = '\0';
    } while(strncmp(input, PASSWORD, 100) != 0);
    return 0;
}