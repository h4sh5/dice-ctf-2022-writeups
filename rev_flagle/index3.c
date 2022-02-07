//gcc -m32 -no-pie ./index3.c -o index3
#include<stdio.h>
#include<stdlib.h>
int main () {
	char value[10];
	fgets(value, 10, stdin);
	value[5] = 0;
	char iVar1,iVar2;

	if (((value[1] * *value == 0x12c0) && (iVar1 = value[2], iVar1 + *value == 0xb2)) &&
              ((iVar1 + value[1] == 0x7e &&
               (((iVar2 = value[3], iVar1 * iVar2 == 0x23a6 && (iVar2 - value[4] == 0x3e)) &&
                (iVar1 * 0x12c0 - value[4] * iVar2 == 0x59d5d)))))) {
		puts("OK!");
	} else {
		puts("Nope!");
	}
}

