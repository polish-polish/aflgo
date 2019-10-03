/* 
 * Simple regular expression matching.
 *
 * From:
 *   The Practice of Programming
 *   Brian W. Kernighan, Rob Pike
 *
 */ 

//#include "klee/klee.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
static int matchhere(char*,char*);

static int matchstar(int c, char *re, char *text) {
  do {
    if (matchhere(re, text))
      return 1;
  } while (*text != '\0' && (*text++ == c || c== '.'));
  return 0;
}

static int matchhere(char *re, char *text) {
  if (re[0] == '\0')
     return 1;
  if (re[1] == '*')
    return matchstar(re[0], re+2, text);
  if (re[0] == '$' && re[1]=='\0')
    return *text == '\0';
  if (*text!='\0' && (re[0]=='.' || re[0]==*text))
    return matchhere(re+1, text+1);
  return 0;
}

int match(char *re, char *text) {
  if (re[0] == '^')
    return matchhere(re+1, text);
  do {
    if (matchhere(re, text))
      return 1;
  } while (*text++ != '\0');
  return 0;
}

/*
 * Harness for testing with KLEE.
 */

// The size of the buffer to test with.
#define SIZE 7

int main(int argc, char** argv) {
  if (argc!=2) //add by yangke
      return -1;//add by yangke
  // The input regular expression.
  char re[SIZE]={[0 ... SIZE-1] ='\0'};
  int  fd = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  int len=read(fd, re, SIZE);
  close(fd);
  if (re[len-1]=='\n') re[len-1]='\0';
  re[SIZE-1]='\0';
  printf("File Content:\n");
  for(int k=0;k<SIZE;k++)
  {
     printf("re[%x]=%x,%c.\n",k,re[k],re[k]);
  }
  // Make the input symbolic. 
  //klee_make_symbolic(re, sizeof re, "re");
  char *key="hello";
  //char *key="<link rel=\"stylesheet\" href=\"/css17/custom.css\" />";
  // Try to match against a constant string "hello".
  if (match(re, key)){
    if(!strcmp(re,key)) return 0;
    if(strlen(re)<6)return 0;//5 is suitable
    int cnt_star=0,cnt_dot=0;
    for(int i=0;i<SIZE;i++){
        if(re[i]=='$')return 0;
        if(re[i]=='*')cnt_star++;
        if(re[i]=='.')cnt_dot++;
    }
    if(cnt_star+cnt_dot>5)return 0;
    printf("Regex Matched!\n");
    abort();//*(int *)0=0;
  }else{
    printf("Regex Not Match!\n");
  }

  //return 0;
}
