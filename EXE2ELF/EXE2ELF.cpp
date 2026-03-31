//EXE2ELF
//Prototype
//© (Repository(https://github.com/adamsnotog/EXE2ELF) creation date) 2025 All credits and rights to Adams @adamsplus1945
//GPLv3
//Code highly sensitive to Original Program alignment and EXE structure standards
//Doesn't support Arm(Bus Error) Rom Big endian
#include"Reading.h"
#include "Name_insertion.h"
#include "elf.h"
int main(){
cout<<BLUE<<"Enter path of exe file: ";
char a=name_insert();
if(a==0){
reading();
elf_writing();
}
	
	
	
	
	
}
