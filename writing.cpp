//EXE2ELF
//WRITING
//Writting.cpp
//Proto
//All credits and rights to Adams @adamsplus1945 
//GPLv3
//Code high sensitivity to Original program alignment and EXE structure standards
//Doesn't support Arm Rom Big endian

#include "exereadingh.h"

exereading exer;
int elf_writing(){
exer.name_store.erase((exer.name_store.size()-3),4);
exer.name_store+=".elf";
ofstream elf(exer.name_store,ios::binary);

if(elf.is_open()!=1){
cout<<"\nunable to convert";
return 7;
}

//ELF HEADER
elf.seekp(0,ios::beg);

char elf_signature[5]="\x7F" "ELF";
elf.write(elf_signature,4);

char elf_class;
if(exer.prog_ver==0x10b){
elf_class=0x01;
}
else{
elf_class=0x02;	
}

elf.write((char*)&elf_class,1);

char class1=0x01;
elf.write(&class1,1);

char data=0x01;
elf.write(&data,1);

char version=0x01;
elf.write(&version,1);

char osabi=0x00;
elf.write(&osabi,1);

char abiversion=0x00;
elf.write(&abiversion,1);

char padding[7]={0,0,0,0,0,0,0};
elf.write(padding,7);
//16 BYTES

short type=0x0002;
elf.write((char*)&type,2);

short elfmachine;
if(exer.archi==0x014c){
elfmachine=0x003;
}
else{
elfmachine=0x3E;	
}

elf.write((char*)&elfmachine,2);

int elfversion=0x00000001;
elf.write((char*)&elfversion,4);

uint64_t elfentry=exer.aep+exer.ib;
elf.write((char*)&elfentry,8);

uint64_t elfphocf=64;
elf.write((char*)&elfphocf,8);

uint64_t elfeshof=0;
elf.write((char*)&elfeshof,8);

int elfflags=0;
elf.write((char*)&elfflags,4);


short elfehsize=64;
elf.write((char*)&elfehsize,2);

short elfphentsize=56;
elf.write((char*)&elfphentsize,2);

short elfphnum=1;
elf.write((char*)&elfphnum,2);

short elfshentsize=0;
elf.write((char*)&elfshentsize,2);

short elfshnum=0;
elf.write((char*)&elfshnum,2);

short elfshstrndx=0;
elf.write((char*)&elfshstrndx,2);


}
