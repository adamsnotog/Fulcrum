//EXE2ELF
//PARSING
//Reading.cpp
//Proto
//All credits and rights to Adams @adamsplus1945 
//GPLv3
//Code high sensitivity to Original program alignment and EXE structure standards
//Doesn't support Arm Rom Big endian
/*Nicknames archi architecture nos number of sections sofoh size of optional header sofid size of initialized data sofuid size of uninitialized data 
aep address of entry point bofc base of code bofd base of data
ib image base sa section alignment fa file alignment mjosv major OS version mnosv minor OS version mjiver major image version mniver minor image version mjsubver major Sub version mnsubver minor Sub version sofoh size of optional header
sofsr size of stack reserve nofras number of RVA and sizes expt export table impt import table rest resource table exct exception table sert security table
brt base relocation debt debug table tlas thread local storage 
boui bound import iat import address table dei delay import clrrh CLR Runtime header 
*/
//Fail states 1 file doesn't open due no data fail 2 file name fail 3 file reading corrupt data fail 
// 4 file doesn't follow recommended requirements fail 
// 5 file not exe fail 6 file missing/corrupt fields fail 7 file doesn't open due corruption/permission file fail 8 file suspicious/unsafe action fail 11 12 13 are levels of danger 13 being most

#pragma pack(1)
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
using namespace std;
class exereading{
public:
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

vector<unsigned char> impt_fields;
vector<unsigned char> lib_name;
//vector <unsigned char> lib
///////////////////
//RVA FUNCTION 
long long rva_offest(long long rva,int* sectable){
int index2=0;
while(index2<960){
if(rva<*(sectable+(index2+3))||rva>*(sectable+(index2+3))+*((sectable+(index2+2)))){
index2+=10;
}
else{
return rva-*(sectable+index2+3)+*(sectable+index2+5);
}
};
return 0;
}
/////////////////

int impt_libraries_num;
vector<int> original_first_thunk;

int rtr;
int reading(){
	
//Block for initializing arrays using for import table and big endiana check
uint16_t lb=0x1234;
char* lbptr=(char*)&lb;
if(*lbptr==0x12){
cout<<"Not designed for Big Endian ";
return 4;	
}			
//Block for file name and content check
cin>>name;
name_store=name;
if(name.size()<=4){cout<<"\nunable to open file";
return 2;
}
name.erase(0,name.size()-4);
transform(name.begin(),name.end(),name.begin(),::tolower);
ifstream file(name_store,ios::binary);
if(name!=".exe"){
vector<uint16_t> mistake(2);
if(file.is_open()==0){
cout<<"\nunable to convert";	
return 5;
}

//Block for Buffers and MZ checking
file.seekg(0,ios::beg);
file.read((char*)&mistake[0],2);
if(*(char*)&mistake[0]=='M'&&*(char*)&mistake[1]=='Z'){cout<<"\nThis file has not an exe extension but it might be an exe file want continue?\n";}
else{cout<<"\nunable to convert";
return 5;
}
char choose;
cin>>choose;
if(choose!='y'&&choose!='Y'){
cout<<"\nExiting Process";
this_thread::sleep_for(chrono::seconds(1));
file.close();
rtr= 0;
}
}
file.seekg(0,ios::end);
file_size=file.tellg();
if(file_size==-1){cout<<"\nunable to convert";
return 7;}
else if(file_size==0){
cout<<"\nunable to convert";
return 1;	
}


//DOS HEADER 60 BYTES 

unsigned char buffer[512];

file.seekg(0,ios::beg);
file.read((char*)buffer,512);
//MZ
if(buffer[0]!='M'&&buffer[1]!='Z'){
cout<<"\nunable to convert";
return 5;
}
//E_LFANEW
if(*(int*)&buffer[60]==0){
cout<<"\nunable to convert";
return 6;
}

if(*(unsigned int*)&buffer[60]>file_size||*(unsigned int*)buffer[60]<65){
cout<<"\nnable to convert";
return 8+5;
}

else{pe_start=*(int*)&buffer[60];}

file.seekg(pe_start,ios::beg);
file.read((char*)buffer,4);
if(buffer[0]!='P'||buffer[1]!='E'||buffer[2]!='\0'||buffer[3]!='\0'){
cout<<"\nunable to convert";
return 6;
}
//6 BYTES IMAGE_FILE_READER / FILE HEADER
file.read((char*)buffer,512);
archi=*(unsigned short*)&buffer[0];
nos=*(unsigned short*)&buffer[2];
//Skipped on 3 Fields 
sofoh=*(unsigned short*)&buffer[16];

file.seekg(pe_start+24,ios::beg);
if(sofoh>512){
cout<<"\nunable to convert";
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
cout<<"\nunable to convert";
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
file.seekg(rva_offest(data_directory[2],(int*)sections_table),ios::beg);
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

//SIGNING THUNKS 		
impt_fields.resize(impt_libraries_num*20);
file.seekg(rva_offest(data_directory[2],(int*)sections_table),ios::beg);
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





file.close();
return rtr;
}
};


uint64_t sofsr;
uint64_t nofras;
uint64_t sectbl32;
uint64_t sectbl64;
uint32_t name_rva;
uint32_t expt;
uint32_t impt;
uint32_t rest;
uint32_t exct;
uint32_t cert;
uint32_t brt;
uint32_t debt;
uint32_t archi2;
uint32_t globptr;
uint32_t tlas;
uint32_t lct;
uint32_t boui;
uint32_t iat;
uint32_t did;
uint32_t clrrh;
uint32_t reserved;
uint32_t expts;
uint32_t impts;
uint32_t rests;
uint32_t excts;
uint32_t certs;
uint32_t brts;
uint32_t debts;
uint32_t archis2;
uint32_t globptrs;
uint32_t tlass;
uint32_t lcts;
uint32_t bouis;
uint32_t iats;
uint32_t dids;
uint32_t clrrhs;
uint32_t reserveds;
uint32_t* ddarr[16]={&expt,&impt,&rest,&exct,&cert,&brt,&debt,&archi2,&globptr,&tlas,&lct,&boui,&iat,&did,&clrrh,&reserved};
uint32_t* ddarrs[16]={&expts,&impts,&rests,&excts,&certs,&brts,&debts,&archis2,&globptrs,&tlass,&lcts,&bouis,&iats,&dids,&clrrhs,&reserveds};
uint32_t* ddarr_size[16];
void reading(){
uint16_t lb=0x1234;
char* lbptr=(char*)&lb;
if(*lbptr==0x12){
cout<<"Not designed for Big Endian ";	
exit(1);
}			
cin>>name;
name_store=name;
if(name.size()<=4){cout<<"\nunable to open file";
exit(1);
}
name.erase(0,name.size()-4);
transform(name.begin(),name.end(),name.begin(),::tolower);
ifstream file(name_store,ios::binary);
if(name!=".exe"){
vector<uint8_t> mistake(2);
char* omistake=(char*)mistake.data();
if(file.is_open()==0){
cout<<"\nunable to convert";	
exit(1);
}
file.seekg(0,ios::beg);
file.read(omistake,2);
if(omistake[0]=='M'&&omistake[1]=='Z'){cout<<"\nThis file has not an exe extension but it might be an exe file want continue?\n";}
else{cout<<"\nunable to convert";
exit(1);
}
char choose;
cin>>choose;
if(choose!='y'&&choose!='Y'){
cout<<"\nExiting Process";
this_thread::sleep_for(chrono::seconds(1));
file.close();
exit(1);
}
}
file.seekg(0,ios::end);
file_size=file.tellg();
if(file_size==-1){cout<<"\nunable to convert";}
else if(file_size==0){
cout<<"\nunable to convert";	
exit(1);
}
vector<uint8_t> buffer(4);
vector<uint8_t> buffer_64(8);
vector<uint8_t> buffer_2 (2);
char* obuffer=(char*)buffer.data();
char* obuffer_64=(char*)buffer_64.data();
char* obuffer_2=(char*)buffer_2.data();
file.seekg(0,ios::beg);
file.read(obuffer,4);
if(buffer[0]!='M'||buffer[1]!='Z'){cout<<"\nunable to convert";
exit(1);
}
file.seekg(0x3c,ios::beg);
file.read(obuffer,4);
pe_start=*(uint32_t*)obuffer;
file.seekg(pe_start,ios::beg);
file.read(obuffer,4);
if(buffer[0]!='P'||buffer[1]!='E'||buffer[2]!='\0'||buffer[3]!='\0'){
cout<<"\nunable to convert";
exit(1);
}
file.seekg(pe_start+4,ios::beg);
file.read(obuffer,2);
uint16_t cpuarch=*(uint16_t*)obuffer;
if(cpuarch==0x014c){
archi=32;	
}
else if(cpuarch==0x8664){
archi=64;	
}
else{cout<<"\nunable to convert ";
exit(1);
}
file.read(obuffer,2);
nos=*(uint16_t*)obuffer;	
file.seekg(20+pe_start,ios::beg);
file.read(obuffer,2);
sofoh=*(uint16_t*)obuffer;
oh_start=pe_start+24;
file.seekg(oh_start,ios::beg);
file.read(obuffer,2);
uint16_t opth=*(uint16_t*)obuffer; 
if(opth==0x10b){
prog_ver=32;
}
else{
prog_ver=64;
}  
file.seekg(4+oh_start,ios::beg);
file.read(obuffer,4);
text_size_sec=*(uint32_t*)obuffer;
file.seekg(8+oh_start,ios::beg);
file.read(obuffer,4);
sofid=*(uint32_t*)obuffer;
file.seekg(12+oh_start,ios::beg);
file.read(obuffer,4);
sofuid=*(uint32_t*)obuffer;
file.seekg(16+oh_start,ios::beg);
file.read(obuffer,4);
aep=*(uint32_t*)obuffer;
file.seekg(20+oh_start,ios::beg);
file.read(obuffer,4);
bofc=*(uint32_t*)obuffer;
if(prog_ver==32){
file.seekg(24+oh_start,ios::beg);
file.read(obuffer,4);
bofd=*(uint32_t*)obuffer;}
if(prog_ver==64){
file.seekg(24+oh_start,ios::beg);
file.read(obuffer_64,8);
ib=*(uint64_t*)obuffer_64;
}
else{
file.seekg(28+oh_start,ios::beg);
file.read(obuffer,4);
ib=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(36+oh_start,ios::beg);	
file.read(obuffer,4);
sa=*(uint32_t*)obuffer;
}
else{
file.seekg(32+oh_start,ios::beg);
file.read(obuffer,4);
sa=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(40+oh_start,ios::beg);	
file.read(obuffer,4);
fa=*(uint32_t*)obuffer;
}
else{
file.seekg(36+oh_start,ios::beg);
file.read(obuffer,4);
fa=*(uint32_t*)obuffer;		
}
if(prog_ver==64){
file.seekg(44+oh_start,ios::beg);	
file.read(obuffer_2,2);
mjosv=*(uint16_t*)obuffer_2;
}
else{
file.seekg(40+oh_start,ios::beg);
file.read(obuffer_2,2);
mjosv=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(46+oh_start,ios::beg);	
file.read(obuffer_2,2);
mnosv=*(uint16_t*)obuffer_2;
}
else{
file.seekg(42+oh_start,ios::beg);
file.read(obuffer_2,2);
mnosv=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(60+oh_start,ios::beg);	
file.read(obuffer,4);
sofi=*(uint32_t*)obuffer;
}
else{
file.seekg(56+oh_start,ios::beg);
file.read(obuffer,4);
sofi=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(64+oh_start,ios::beg);	
file.read(obuffer,4);
sofh=*(uint32_t*)obuffer;
}
else{
file.seekg(60+oh_start,ios::beg);
file.read(obuffer,4);
sofh=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(72+oh_start,ios::beg);	
file.read(obuffer_2,2);
subsys=*(uint16_t*)obuffer_2;
}
else{
file.seekg(68+oh_start,ios::beg);
file.read(obuffer_2,2);
subsys=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(74+oh_start,ios::beg);	
file.read(obuffer_2,2);
dllchar=*(uint16_t*)obuffer_2;
}
else{
file.seekg(70+oh_start,ios::beg);
file.read(obuffer_2,2);
dllchar=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(80+oh_start,ios::beg);	
file.read(obuffer_64,8);
sofsr=*(uint64_t*)obuffer_64;
}
else{
file.seekg(72+oh_start,ios::beg);
file.read(obuffer,4);
sofsr=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(108+oh_start,ios::beg);	
file.read(obuffer,4);
nofras=*(uint32_t*)obuffer;
}
else{
file.seekg(92+oh_start,ios::beg);
file.read(obuffer,4);
nofras=*(uint32_t*)obuffer;	
}
int dd32=oh_start+96;
int dd64=oh_start+112;
int off_ind=0;
int element=0;
int element2=0;
while(element2<16){
if(prog_ver==64){
file.seekg(dd64+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarr[element])=*(uint32_t*)obuffer;
off_ind+=4;
element++;
file.seekg(dd64+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarrs[element2])=*(uint32_t*)obuffer;
off_ind+=4;
element2++;
}
else{
file.seekg(dd32+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarr[element])=*(uint32_t*)obuffer;
off_ind+=4;
element++;
file.seekg(dd32+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarrs[element2])=*(uint32_t*)obuffer;
off_ind+=4;
element2++;
}
};
file.seekg(12+dd32,ios::beg);
file.read(obuffer,4);
name_rva=*(uint32_t*)obuffer;

}

};


    
