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
printf("%d\n", sizeof(Elf64_Phdr));
printf("%d\n", sizeof(Elf64_Ehdr));
printf("%d\n", sizeof(Elf64_Off));

}