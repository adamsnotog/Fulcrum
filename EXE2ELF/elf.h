//ELF WRITING
#pragma once
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int elf_writing(){
extern string name;
extern string name_store;
extern string name_store2;
extern long long file_size;
extern unsigned char sections_table[];
extern unsigned short prog_ver;
extern int aep;
extern uint64_t ib;
extern char no_ext;
ifstream file(name_store2,ios::binary);
string elf_name=name_store;
if(no_ext==1){
elf_name+=".elf";
}
else{
elf_name.erase((name_store2.size()-4),5);
elf_name+=".elf";
}


ofstream elf(elf_name,ios::binary);


if(elf.is_open()!=1){
cout<<"\nunable to convert\npermission denied (cannot open file correctly) ";
return 7;
}


//ELF HEADER
elf.seekp(0,ios::beg);
//ELF identity 64
if(prog_ver==64){
char elf_signature[5]="\x7F" "ELF";
elf.write(elf_signature,4);

char elf_class=0x02;	
elf.write((char*)&elf_class,1);

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


//File Properties
short type=0x02;
elf.write((char*)&type,2);

short elfmachine;
elfmachine=0x3E;	
elf.write((char*)&elfmachine,2);

int elfversion=0x01;
elf.write((char*)&elfversion,4);

uint64_t elfentry=aep+ib;
elf.write((char*)&elfentry,8);
//16 BYTES


//Segments identity/Program Headers
uint64_t elfphoff=64;
elf.write((char*)&elfphoff,8);

uint64_t elfeshoff=0;
elf.write((char*)&elfeshoff,8);

int e_flags=0;
elf.write((char*)&e_flags,4);

short e_ehsize=64;
elf.write((char*)&e_ehsize,2);

short e_phentsize=56;
elf.write((char*)&e_phentsize,2);

short e_phnum=1;
elf.write((char*)&e_phnum,2);

short e_shentsize=64;
elf.write((char*)&e_shentsize,2);

short e_shnum=0;
elf.write((char*)&e_shnum,2);

short e_shstrndx=0;
elf.write((char*)&e_shstrndx,2);
//32 BYTES



//SEGMENT IDENTITY
int p_type=1;
elf.write((char*)&p_type,4);

int p_flags=7;
elf.write((char*)&p_flags,4);

uint64_t p_offset=4096;
elf.write((char*)&p_offset,8);

uint64_t p_vaddr=ib+0x1000;
elf.write((char*)&p_vaddr,8);

uint64_t p_paddr=0;
elf.write((char*)&p_paddr,8);

uint64_t p_filesz=file_size;
elf.write((char*)&p_filesz,8);

uint64_t p_memsz=file_size+0x1000;
elf.write((char*)&p_memsz,8);

uint64_t p_align=0x1000;
elf.write((char*)&p_align,8);


//120 BYTES

char padding2[4095-120];
short index55=0;
while(index55<=3974){
padding2[index55]=0;
index55++;
}

elf.write(padding2,4095-120);





}


//ELF identity 32
if(prog_ver==32){
char elf_signature[5]="\x7F" "ELF";
elf.write(elf_signature,4);

char elf_class=0x01;	
elf.write((char*)&elf_class,1);

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


//File Properties
short type=0x02;
elf.write((char*)&type,2);

short elfmachine;
elfmachine=0x03;	
elf.write((char*)&elfmachine,2);

int elfversion=0x01;
elf.write((char*)&elfversion,4);

uint32_t elfentry=aep+ib;
elf.write((char*)&elfentry,4);
//12 BYTES


//Segments identity/Program Headers
int elfphoff=52;
elf.write((char*)&elfphoff,4);

int elfeshoff=0;
elf.write((char*)&elfeshoff,4);

int e_flags=0;
elf.write((char*)&e_flags,4);

short e_ehsize=52;
elf.write((char*)&e_ehsize,2);

short e_phentsize=32;
elf.write((char*)&e_phentsize,2);

short e_phnum=1;
elf.write((char*)&e_phnum,2);

short e_shentsize=40;
elf.write((char*)&e_shentsize,2);

short e_shnum=0;
elf.write((char*)&e_shnum,2);

short e_shstrndx=0;
elf.write((char*)&e_shstrndx,2);
//32 BYTES



//SEGMENT IDENTITY
int p_type=1;
elf.write((char*)&p_type,4);

int p_offset=4096;
elf.write((char*)&p_offset,4);

int p_vaddr=ib+0x1000;
elf.write((char*)&p_vaddr,4);

int p_paddr=0;
elf.write((char*)&p_paddr,4);

int p_filesz=file_size;
elf.write((char*)&p_filesz,4);

int p_memsz=file_size+0x1000;
elf.write((char*)&p_memsz,4);

int p_flags=7;
elf.write((char*)&p_flags,4);

int p_align=0x1000;
elf.write((char*)&p_align,4);
//84 BYTES

int elf_filesize=elf.tellp();
char padding2[4095-elf_filesize];
short index55=0;
while(index55<4095-elf_filesize){
padding2[index55]=0;
index55++;
}

elf.write(padding2,4095-elf_filesize);



}



/////////////////////////
//CODE

int sectrva;
int index33=0;
char possibility=0;
while(possibility!=100&&index33<=3840){
if(possibility==10){
possibility=0;
}
if((*(int*)&sections_table[index33]==*(int*)".tex"&&sections_table[(index33+4)]=='t')||*(int*)&sections_table[index33]==*(int*)"text"){
possibility+=10;
}
if(*(int*)&sections_table[index33+36]==0x60000020){
possibility+=100;	
}
index33+=40;
}
char no_text=0;
if(possibility<100){
no_text=1;
}
index33/=40;
int index34=0;
unsigned char* arr2=new unsigned char[(int)sections_table[index33+16]];
file.seekg((int)sections_table[index33+5],ios::beg);
file.read((char*)&arr2[index34],(int)sections_table[index33+4]);
elf.write((char*)arr2,(int)sections_table[index33+4]);







delete[] arr2;



elf.close();

}
/***
VERY IMPORTANT DUE TO COMPLEXITY OF MULTI PERMISSIONS OF EACH SEGMENT , 
THE SINGLE PERMISSION FOR DIFFERENT SEGMENTS METHOD USED R+E+W WHICH WILL MAKE FILE SO MUCH EASY AND MORE PROBABLY TO GET HACKED!
***/
