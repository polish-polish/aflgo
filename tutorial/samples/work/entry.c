#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#define SEC_LEN 18
int* i;
void addOne(int * p)
{
	*p+=1;
        printf("j=%d\n",*p);
}
void addTwo(int * p)
{
	*p+=2;printf("j=%d\n",*p);
}
int main(int argc, char** argv)
{
  int  j = 0;
  char local[SEC_LEN]={[0 ... SEC_LEN-1] ='\0'};
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

  read(fd1, local, SEC_LEN);
  printf("File Content:\n");
  for(int k=0;k<SEC_LEN;k++)
  {
     printf("local[%d]=%d.\n",k,local[k]);
  }
  if (local[7] == 'B' && local[8] == 'a') {
      addOne(&j);
  }
  if (local[9] == 'i' && local[3] == '8') {
      addTwo(&j);
  }/*
  if (local[4] == '6' ) {
      addTwo(&j);
  }*/
  
  if (j != 3) {
      i = (int*) malloc(sizeof(int));
      printf("j=%d,Fine.\n",j);
  }else
  {
      printf("j=%d,Oops! You find the memory miss allocation bug!\n",j);
  }
  *i = 2;
  return 0;
}
