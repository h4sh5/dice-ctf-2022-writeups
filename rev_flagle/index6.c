//gcc -m32 -no-pie ./index6.c -o index6
#include<stdio.h>
#include<stdlib.h>
int main () {
	char value[10];
	fgets(value, 10, stdin);
	value[5] = 0;
	// char iVar1,iVar2;

	if ((((value[1] + 0xb75) * (*value + 0x6e3) == 0x53acdf) && (value[4] == '}')) &&
                 ((value[3] + 0x60a) * (value[2] + 0xf49) == 0x62218f)) {
		puts("OK!");
	} else {
		puts("Nope!");
	}
}

