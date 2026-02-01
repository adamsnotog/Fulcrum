#include "exereadingh.h"
exereading exes;
void sections_write(){
ifstream file2(exes.name_store,ios::binary);
char sections_name[9]={"SECTIONS"};
ofstream file3((char*)sections_name,ios::binary);

int index3=0;
char padding2[512];
memset(padding2,0,512);

file3.seekp(0,ios::beg);

for(;index3<exes.nos*40;){
file3.write((char*)&exes.sections_table[index3],8);
file3.write("-",1);
file3.write((char*)&exes.sections_table[index3+8],4);
file3.write("-",1);
file3.write((char*)&exes.sections_table[index3+12],4);
file3.write("-",1);
file3.write((char*)&exes.sections_table[index3+16],4);
file3.write("-",1);
file3.write((char*)&exes.sections_table[index3+20],4);
file3.write("-",1);
file3.write((char*)&exes.sections_table[index3+36],4);
index3+=40;
if(index3<(exes.nos-1)*40){
file3.write(padding2,(*(int*)&exes.sections_table[(index3+16)-40])%512);
}

}






}