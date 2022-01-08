# include <elf.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# include <ar.h>
# include <stdio.h>
# include <elf.h>

int main()
{
printf("%d\n", O_RDWR | O_CREAT | O_TRUNC);
printf("%d\n", S_IRWXO | S_IRWXU | S_IRWXG);

}