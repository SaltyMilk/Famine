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
printf("%d\n",MAP_FAILED);
printf("%d\n", PROT_READ);
printf("%d\n", MAP_PRIVATE);
printf("sz=%d\n", sizeof(Elf32_Ehdr));

}