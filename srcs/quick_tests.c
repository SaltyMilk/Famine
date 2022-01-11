# include <elf.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# include <ar.h>
# include <stdio.h>
# include <elf.h>

char s[44] = "\xbf\x01\x00\x00\x00\x48\xb8\x48\x41\x43\x4b\x45\x44\x0a\x00\x50\x48\x89\xe6\xba\x07\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\xb8\x3c\x00\x00\x00\xbf\x13\x00\x00\x00\x0f\x05";
int main()
{
printf("%d\n", PF_X | PF_R);

//	int fd = open("sc", O_RDWR | O_CREAT | O_TRUNC, 0777);
//	write(fd, s, 45);
}