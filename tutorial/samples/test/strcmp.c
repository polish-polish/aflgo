#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SEC_LEN 27

int main(int argc, char** argv)
{
  int  j = 0;
  char local[SEC_LEN]={[0 ... SEC_LEN-1] ='\0'};
  char local2[SEC_LEN]={[0 ... SEC_LEN-1] ='\0'};
  if (argc!=2)//add by yangke
     return -1;//add by yangke
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

  read(fd1, local, SEC_LEN);
  printf("File Content:%s\n",local);
  int sum=0;
  unsigned char *p=local;
  while(*p){
     sum+=*p++;
  }
  if(strcmp(local,"apple")==0){
	if(strcmp(local+6,"banana")==0){
		if(strcmp(local+13,"12")==0){
			if(strcmp(local+16,"")==0){
				//strcpy(local2,local);
				printf("%ld,sum=%d",strchr(local,'\0')-local,sum);
				abort();
			}
		}
	}
  }
  return 0;
}
