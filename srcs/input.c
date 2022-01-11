#include <stdio.h>
#include <string.h>
int main()
{
	char s[64];
	bzero(s, 64);
	printf("Enter your name: ");
	fgets(s, 63, stdin);
	printf("Welcome %s", s);
}
