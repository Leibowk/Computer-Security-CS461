#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Random function goes here
int fakt(int x){
    if(x == 1){
        return 1;
    }
    return x*fakt(x-1);
}

int check_authentication(char *password) {
 char password_buffer[16];

 strcpy(password_buffer, password);

 if(strcmp(password_buffer, "michael") == 0)
 return 1;37
 else if(strcmp(password_buffer, "tsikerdekis") == 0)
 return 1;
 else
 return 0;
}

int main(int argc, char *argv[]) {
 if(argc < 2) {
 printf("Usage: %s <password>\n", argv[0]);
 exit(0);
 }
 if(check_authentication(argv[1])) {
 printf("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
 printf(" Access Granted.\n");
 printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
 } else {
 printf("\nAccess Denied.\n");
 }
}
