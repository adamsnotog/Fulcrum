//EXE2ELF
//Name_Insertion.h

#include "reading.h"
using namespace std;
int name_insert(){
//Block for file name and content check
cout<<GREEN;
getline(cin,name);
cout<<RESET;
name_store=name;
if(name.size()<1||name_store[0]==' '){cout<<RED<<"\nunable to open file\n"<<YELLOW<<"invalid name (name is short)"<<RESET;
return 2;
}
if(name.size()>4){
name.erase(0,name.size()-4);
transform(name.begin(),name.end(),name.begin(),::tolower);}
//CHANCE CHECK
char anything=0;
name_store2=name_store;
if(name!=".exe"){
no_ext=1;
name_store2=name_store+".exe";
if(name_store[name_store.size()-1]==' '&&no_ext==1){
name_store.erase(name_store.size()-1,1);
name_store2=name_store+".exe";
}
vector<char> mistake(2);
if(1){
ifstream file(name_store,ios::beg);
if(file.is_open()==0){
ifstream file1(name_store2,ios::beg);
if(file1.is_open()==0){
cout<<RED<<"\nunable to convert\n"<<YELLOW<<"an error occurred (unknown error can't open file/file not found) "<<RESET;	
return 6;
}
file1.close();
file.close();
}
}

ifstream file(name_store2,ios::binary);
//Block for Buffers and MZ checking
file.seekg(0,ios::beg);
file.read((char*)&mistake[0],2);
if(mistake[0]=='M'&&mistake[1]=='Z'){
cout<<GREEN<<*(char*)&mistake[0]<<*(char*)&mistake[1]<<GREEN<<" <-An EXE Program";
cout<<GREEN<<"\nThis file's extension is not exe , but it might be an exe file \nwant continue "<<BLUE<<"("<<BLUE<<"Y"<<BLUE<<"/"<<BLUE<<"N"<<BLUE<<")\n"<<RESET;
}
else{
ifstream file(name_store,ios::binary);
file.read((char*)&mistake[0],2);
cout<<RED<<*(char*)&mistake[0]<<*(char*)&mistake[1]<<YELLOW<<" <-Not an EXE program";
cout<<RED<<"\nunable to convert\n"<<YELLOW<<"file is not exe file (No MZ Magic Number) "<<RESET;
return 5;
}


int index56=0;
string choose;
a10:
cout<<GREEN;
getline(cin,choose);
cout<<RESET;
a11:
if(choose[0]=='n'&&choose.size()==1||choose[0]=='N'&&choose.size()==1||choose=="No"||choose=="no"||anything==1){
struct termios tty;
tcgetattr(STDIN_FILENO, &tty);
tty.c_lflag&= ~ECHO;
tty.c_lflag &= ~ICANON;
cout<<"\033[?25l";
tcsetattr(STDIN_FILENO, TCSANOW, &tty); 
cout<<BLUE<<"\nExiting Process."<<flush;
this_thread::sleep_for(chrono::milliseconds(200));
cout<<"."<<flush;
this_thread::sleep_for(chrono::milliseconds(200));
cout<<"."<<flush;
this_thread::sleep_for(chrono::milliseconds(200));
cout<<"."<<RESET<<flush;
this_thread::sleep_for(chrono::milliseconds(1100));
file.close();
return -1;
}
if(choose[0]!='Y'&&choose[0]!='y'&&choose!="yes"&&choose!="Yes"){
index56++;
if(index56>3){
anything=1;
goto a11;
}
cout<<"\033[A\033[D\033[0J";
if(index56==1){
cout<<YELLOW<<"Choose valid option (Y/N)\n";
goto a10;
}
goto a10;
}



}


return 0;
}
