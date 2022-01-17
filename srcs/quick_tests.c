# include <elf.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# include <ar.h>
# include <stdio.h>
# include <elf.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>


#define SC_LEN 44
char s[SC_LEN] = "\x57\x56\x51\x53\x50\x52\xbf\x01\x00\x00\x00\x48\xb8\x48\x41\x43\x4b\x45\x44\x0a\x00\x50\x48\x89\xe6\xba\x07\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\x5a\x58\x5b\x59\x5e\x5f";
int main()
{

printf("%d\n", sizeof(sa_family_t));
printf("%d\n", sizeof(in_port_t));
printf("%d\n", sizeof(struct in_addr));
printf("%d\n", sizeof(struct sockaddr_in));

printf("%d\n", htons(4219));
printf("%d\n", inet_addr("127.0.0.1"));
	int fd = open("sc", O_RDWR | O_CREAT | O_TRUNC, 0777);
	write(fd, s, SC_LEN);
}