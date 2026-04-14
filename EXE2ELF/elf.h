//ELF WRITING
#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
using namespace std;
extern string name;
extern string name_store;
extern string name_store2;
extern long long file_size;
extern unsigned short nos;
extern unsigned char sections_table[];
extern unsigned short prog_ver;
extern unsigned short archi;
extern int aep;
extern uint64_t rva_offset(uint64_t rva,int* sectable);
extern bool flag1;
extern const string RED;
extern const string BLUE;
extern const string RESET;
extern uint64_t ib;
extern char no_ext;
//fstream file;
//ofstream elf;
char flag2=0;
int index33;
/*
This function isn't needed anymore but decided to left it
int get_power(int val,bool give_power,int* dest_val){
if(val>0&&dest_val!=nullptr){
int temp_ind=0;
while(val>=10){
val/=10;
temp_ind++;
}
if(give_power==false){
return temp_ind;
}
else{
while(temp_ind>0){
*dest_val*=10;
temp_ind--;
}
}
}
else{
return -1;
}
}
*/

////////////////////////////////////////////////////////////////////////
int text_sec(){
	
index33=0;
char possibility=0;
char no_doubt=0;
while(possibility<=70&&index33<nos*40){
if(possibility==10){
possibility=0;
}
if((*(int*)&sections_table[index33]==*(int*)".tex"&&sections_table[(index33+5)]=='t')||*(int*)&sections_table[index33]==*(int*)"text"){
possibility+=10;
}
if(*(int*)&sections_table[index33+36]==0x60000020){
possibility+=30;	
}
if(aep>=*(int*)&sections_table[index33+12]&&aep<=*(int*)&sections_table[index33+8]){
possibility+=70; 
no_doubt++;
return 0;
}
index33+=40;
}



char no_text=0;
if(possibility>=30){
return 0;
}
else{
return 1;	
}

}


///////////////////////////////////////////////////////////////////////

//The logic is to get the file position to put sections
int sections_placement(ofstream *file,unsigned char* sects_data ,int sizeof_sec,int position,unsigned char* sectable,char whichsec){
int index66=0;
unsigned int sects_rvas[nos];
//Initializing Sections VAs
while(index66<nos){
sects_rvas[index66]=*(int*)&sectable[(index66*40)+12];	
index66++;
}

//Sorting Array VAs 
sort(sects_rvas,&sects_rvas[nos]);

file->seekp(position,ios::beg);
//The logic is to get the wanted section number in order of section table then copy it
if(whichsec>96||whichsec>nos||whichsec<0){
return -1;
}
file->write((char*)sects_data,sizeof_sec);

}

///////////////////////////////////////////////////////////////////////


/*int reloc_trans(ifstream* elf,ofstream* file){
file.seek
	
}*/




///////////////////////////////////////////////////////////////////////


int elf_writing(){
if(1){
string elf_name=name_store;
if(no_ext==1){
elf_name+=".elf";
}
else{
elf_name.erase((name_store2.size()-4),5);
elf_name+=".elf";
}

ifstream file(name_store2,ios::binary);
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

}
int elf_filesize=elf.tellp();
char padding2[4096];
short index55=0;
while(index55<4095-elf_filesize){
padding2[index55]=0;
index55++;
}

elf.write(padding2,4095-elf_filesize);






int index77=0;
unsigned char *sect_data=new unsigned char[(double)file_size];
int pos=elf_filesize;
while(index77<nos){
file.seekg(*(int*)&sections_table[((index77*40)+20)],ios::beg);
file.read((char*)sect_data,*(int*)&sections_table[(index77*40)+16]);
sections_placement(&elf,sect_data,*(int*)&sections_table[((index77*40)+16)],pos,sections_table, index77);
pos+=*(int*)&sections_table[(index77*40)+16];
//elf.write((char*)padding2,*(int*)&sections_table[(index77*40)+16]%512);
index77++;
}


flag1=true;


delete[] sect_data;
elf.close();

}
return 0;
}
/***
VERY IMPORTANT DUE TO COMPLEXITY OF MULTI PERMISSIONS OF EACH SEGMENT , 
THE SINGLE PERMISSION FOR DIFFERENT SEGMENTS METHOD USED R+E+W WHICH WILL MAKE FILE SO MUCH EASY AND MORE PROBABLY TO GET HACKED!
***/





//CREDITS TO ORIGINAL DEVELOPER ADAMS @Adamsplus1945
