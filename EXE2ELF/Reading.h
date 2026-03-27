//EXE2ELF
//PARSING
//Reading.h
//prototype
//© (Repository creation date) 2025 All credits and rights to Adams @adamsplus1945
//GPLv3
//Code highly sensitive to Original Program alignment and EXE structure standards
//Doesn't support Arm(Bus Error) Rom Big endian
/*Nicknames
 archi architecture nos number of sections sofoh size of optional header sofid size of initialized data sofuid size of uninitialized data 
aep address of entry point bofc base of code bofd base of data
ib image base sa section alignment fa file alignment mjosv major OS version mnosv minor OS version mjiver major image version mniver minor image version mjsubver major Sub version mnsubver minor Sub version sofoh size of optional header
sofsr size of stack reserve nofras number of RVA and sizes expt export table impt import table rest resource table exct exception table sert security table
brt base relocation debt debug table tlas thread local storage 
boui bound import iat import address table dei delay import clrrh CLR Runtime header 
*/
//Fail states 1 file doesn't open due no data fail 2 file name fail 3 file reading corrupt data fail 
// 4 file doesn't follow recommended requirements fail 
// 5 file not exe fail 6 file missing/corrupt fields fail 7 file doesn't open due corruption/permission file fail 8 file suspicious/unsafe action fail 11 12 13 are levels of danger 13 being most

#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <ctime>
#include <termios.h>
#include <unistd.h>
#include <limits>
using namespace std;
string name;
string name_store;
long long file_size;
unsigned int pe_start;
unsigned short archi;
unsigned short nos;
unsigned short sofoh;
unsigned short prog_ver;
int sofc;
int sofid;
int sofuid;
int aep;
int bofc;
int bofd;
uint64_t ib;
uint64_t sa;
uint64_t fa;
uint64_t mjosv;
uint64_t mnosv;
uint64_t mjiver;
uint64_t mniver;
uint64_t mjsubver;
uint64_t mnsubver;
uint64_t win32_ver_val;
uint64_t sofi;
uint64_t sofh;
uint64_t check_sum;
uint64_t sofsc;
uint64_t sofhr;
uint64_t sofhc;
uint64_t subsys;
uint64_t dllchar;
uint64_t sofsr;
uint64_t nofras;
uint64_t sectbl32;
uint64_t sectbl64;
uint32_t name_rva;
int loader_flags;

unsigned char sections_table[96*40];
unsigned int data_directory[32];
unsigned char buffer4096[4096];

bool flag1=false;

vector<unsigned char> impt_fields;
vector<unsigned char> lib_name;
//vector <unsigned char> lib
///////////////////
//RVA FUNCTION 
uint64_t rva_offset(uint64_t rva,int* sectable){
int index2=0;
while(index2<960){
if(rva<*(sectable+(index2+3))||rva>*(sectable+(index2+3))+*((sectable+(index2+2)))){
index2+=10;
}
else{
if(*(sectable+index2+2)==0){
return 0;
}
else{
return rva-*(sectable+index2+3)+*(sectable+index2+5);
}
}
};
return 0;
}
/////////////////

const string BLUE="\033[1;34m";
const string RED="\033[1;31m";
const string YELLOW="\033[1;33m";
const string GREEN="\033[1;32m";
const string RESET="\033[0m";


int impt_libraries_num;
vector<int> original_first_thunk;
vector<int> impt_iat;
string name_store2;
char no_ext=0;
int rtr;
int reading(){
//Block for initializing arrays using for import table and big endian check
uint16_t lb=0x1234;
char* lbptr=(char*)&lb;
if(*lbptr==0x12){
cout<<YELLOW<<"Not designed for Big Endian ";
return 4;	
}			

ifstream file(name_store2,ios::beg);
file.seekg(0,ios::end);
file_size=file.tellg();
if(file_size==-1){cout<<YELLOW<<"\nunable to convert\n"<<"permission denied (cannot open file correctly) ";
return 7;}
else if(file_size==0){
cout<<YELLOW<<"\nunable to convert\nno data (file is empty) ";
return 1;}

//DOS HEADER 60 BYTES 

unsigned char buffer[512];

file.seekg(0,ios::beg);
file.read((char*)buffer,512);
//MZ
if(buffer[0]!='M'&&buffer[1]!='Z'){
cout<<YELLOW<<"\nunable to convert\nfile is not exe file (no MZ signature) ";
return 5;
}
//E_LFANEW
if(*(int*)&buffer[60]==0){
cout<<YELLOW<<"\nunable to convert\nfile is corrupted (E_LFANEW) ";
return 6;
}

if(*(unsigned int*)&buffer[60]>file_size||*(unsigned int*)&buffer[60]<65){
cout<<YELLOW<<"\nunable to convert\n"<<RED<<"FILE IS \nSUPER SUSPICIOUS (MALWARE E_LFANEW) ! "<<(int)buffer[60];
return 8+5;
}

pe_start=*(int*)&buffer[60];

file.seekg(pe_start,ios::beg);
file.read((char*)buffer,4);
if(buffer[0]!='P'||buffer[1]!='E'||buffer[2]!='\0'||buffer[3]!='\0'){
cout<<YELLOW<<"\nunable to convert\nfile is not exe file (PE\0\0) ";
return 6;
}
//6 BYTES IMAGE_FILE_HEADER / FILE HEADER
file.read((char*)buffer,512);
archi=*(unsigned short*)&buffer[0];
nos=*(unsigned short*)&buffer[2];
//Skipped on 3 Fields 
sofoh=*(unsigned short*)&buffer[16];

file.seekg(pe_start+24,ios::beg);
if(sofoh>512){
cout<<YELLOW<<"\nunable to convert\n"<<RED<<"FILE IS SUSPICIOUS (SIZE OF OPTIONAL HEADER) !";
return 8+4;	
}


//OPTIONAL HEADER 

file.read((char*)buffer,512);

if(*(unsigned short*)&buffer[0]==0x10b){
prog_ver=32;
}

else if(*(unsigned short*)&buffer[0]==0x20b){
prog_ver=64;	
}

if(prog_ver!=32&&prog_ver!=64){
cout<<YELLOW<<"\nunable to convert\nfile is corrupted (program version) ";
return 6;
}

sofc=*(int*)&buffer[4];

sofid=*(int*)&buffer[8];

sofuid=*(int*)&buffer[12];

aep=*(int*)&buffer[16];

bofc=*(int*)&buffer[20];

if(prog_ver==32){
bofd=*(int*)&buffer[24];
}

////////////////////////
if(prog_ver==32){
file.seekg(-(512-28),ios::cur);
}
else{
file.seekg(-(512-24),ios::cur);
}
file.read((char*)buffer,512);

//This make IMAGE BASE element 0 in both 32 64

///////////////////
//SECTION TABLE AND DATA DIRECTORY 
switch(prog_ver){
case 32:{
ib=*(int*)&buffer[0];
sa=*(int*)&buffer[4];
fa=*(int*)&buffer[8];
mjosv=*(unsigned short*)&buffer[12];
mnosv=*(unsigned short*)&buffer[14];
mjiver=*(unsigned short*)&buffer[16];
mniver=*(unsigned short*)&buffer[18];
mjsubver=*(unsigned short*)&buffer[20];
mnsubver=*(unsigned short*)&buffer[22];
win32_ver_val=*(int*)&buffer[24];
sofi=*(int*)&buffer[28];
sofh=*(int*)&buffer[32];
check_sum=*(int*)&buffer[36];
subsys=*(unsigned short*)&buffer[40];
dllchar=*(unsigned short*)&buffer[42];
nofras=*(int*)&buffer[64];
//DATA DIRECTORIES 
int index1=0;
int index2=68;
//128+68=196
while(index2<196){
data_directory[index1]=*(unsigned int*)&buffer[index2];
index1++;
index2+=4;
};

}
/////////
break;	


//////////////////////////////////////

case 64:{
ib=*(unsigned long long*)&buffer[0];
sa=*(int*)&buffer[8];
fa=*(int*)&buffer[12];
mjosv=*(unsigned short*)&buffer[16];
mnosv=*(unsigned short*)&buffer[18];
mjiver=*(unsigned short*)&buffer[20];
mniver=*(unsigned short*)&buffer[22];
mjsubver=*(unsigned short*)&buffer[24];
mnsubver=*(unsigned short*)&buffer[26];
win32_ver_val=*(int*)&buffer[28];
sofi=*(int*)&buffer[32];
sofh=*(int*)&buffer[36];
check_sum=*(int*)&buffer[40];
subsys=*(unsigned short*)&buffer[44];
dllchar=*(unsigned short*)&buffer[46];
sofsr=*(unsigned long long*)&buffer[48];
sofsc=*(unsigned long long*)&buffer[56];
sofhr=*(unsigned long long*)&buffer[64];
loader_flags=*(int*)&buffer[80];
nofras=*(int*)&buffer[84];
//DATA DIRECTORIES 
int index1=0;
int index2=88;
//128+88=216
while(index2<216){
data_directory[index1]=*(unsigned int*)&buffer[index2];
index1++;
index2+=4;
};


}
/////////////////////

break;

}




/////////////////
//TO MAKE BUFFER4096 STARTS FROM SECTION TABLE 
switch(prog_ver){
case 32:file.seekg(-(512-196),ios::cur);
file.read((char*)buffer4096,4096);
break;
case 64:file.seekg(-(512-216),ios::cur);
file.read((char*)buffer4096,4096);
break;
}
////////////////


//SECTION TABLE 

memcpy(sections_table,buffer4096,nos*40);

//REAL SECTIONS END
file.seekg(-(4096-(nos*40)),ios::cur);

//IMPORT TABLE/DIRECTORY 
file.seekg(rva_offset(data_directory[2],(int*)sections_table),ios::beg);
unsigned char buffer_impt[20];
int index1=0;
int index2=0;
//COUNTING LIBRARIES NUMBER
while(index1<10000){
	
if(index2==0){
file.read((char*)buffer_impt,20);
}

if(buffer_impt[index2]==0){
index2++;
}
if(index2==19){break;}
else{
index1++;
index2=0;
}

};
impt_libraries_num=index1;

//READING/FILLING THUNKS 		
impt_fields.resize(impt_libraries_num*20);
file.seekg(rva_offset(data_directory[2],(int*)sections_table),ios::beg);
index1=0;
index2=0;
file.read((char*)&impt_fields[0],20*impt_libraries_num);

//OG FIRST THUNK
original_first_thunk.resize(impt_libraries_num);
while(index1<impt_libraries_num){
memcpy(&original_first_thunk[index1],&impt_fields[index2],4);
index1++;
index2+=5;
}


//LIBRARIES NAME
index1=0;index2=0;
lib_name.resize(impt_libraries_num);
while(index1<impt_libraries_num){
memcpy(&lib_name[index1],&impt_fields[index2+3],4);
index1++;
index2+=5;
}


//IAT
index1=0;index2=0;
impt_iat.resize(impt_libraries_num);
while(index1<impt_libraries_num){
memcpy(&lib_name[index1],&impt_fields[index2+4],4);
index1++;
index2+=5;
}








file.close();


struct termios tty;
tcgetattr(STDIN_FILENO, &tty);
tty.c_lflag&= ~ECHO;
tty.c_lflag &= ~ICANON;
cout<<"\033[?25l";
tcsetattr(STDIN_FILENO, TCSANOW, &tty); 
cout<<BLUE<<"\n\nProcess Has Done Successfully."<<RESET;

flag1=true;
;


}
//Why not using windows.h structures? because the code meant to work on linux
//Why not using full name of enums instead of stall numbers? because the code built within weeks and not full time work
//Most important Why code not perfect? because it built on android and free compiler 

/***Still in development***/