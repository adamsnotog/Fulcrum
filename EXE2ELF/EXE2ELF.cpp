//EXE2ELF
#include"Reading.h"
#include "Name_insertion.h"
#include "elf.h"
int main(){
char buffer[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    
    if (length != -1) {
        buffer[length] = '\0';
        string fullPath(buffer);

        size_t lastSlashPos = fullPath.find_last_of("/");
        string directoryPath = fullPath.substr(0, lastSlashPos);

        string logoPath = directoryPath + "/logo/logo.png";

    }
	

char a=name_insert();
if(a==0){
reading();
elf_writing();
}
	
	
	
	
	
}