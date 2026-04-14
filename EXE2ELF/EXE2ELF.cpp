//EXE2ELF
//Prototype
//© (Repository(https://github.com/adamsnotog/Fulcrum) creation date) 2025 All credits and rights to Adams @adamsplus1945
//GPLv3 
//Code highly sensitive to Original Program alignment and EXE structure standards
//Doesn't support Arm(Bus Error) Rom Big endian
#include"Reading.h"
#include "Name_insertion.h"
#include "elf.h"
int main(){
cout<<BLUE<<"Enter path of exe file: ";
char a=name_insert();
int b;
if(a==0){
b=reading();
}
if(b==0){
char c=elf_writing();	
if(c==0){
struct termios tty;
tcgetattr(STDIN_FILENO, &tty);
tty.c_lflag&= ~ECHO;
tty.c_lflag &= ~ICANON;
cout<<"\033[?25l";
tcsetattr(STDIN_FILENO, TCSANOW, &tty); 
cout<<BLUE<<"\n\nProcess Has Done Successfully."<<RESET;
}
else if(c==20){
struct termios tty;
tcgetattr(STDIN_FILENO, &tty);
tty.c_lflag&= ~ECHO;
tty.c_lflag &= ~ICANON;
cout<<"\033[?25l";
tcsetattr(STDIN_FILENO, TCSANOW, &tty); 
cout<<RED<<"\n\nSection size is so big or the section is corrupted";
}
else if(c==3){
struct termios tty;
tcgetattr(STDIN_FILENO, &tty);
tty.c_lflag&= ~ECHO;
tty.c_lflag &= ~ICANON;
cout<<"\033[?25l";
tcsetattr(STDIN_FILENO, TCSANOW, &tty); 
cout<<RED<<"\nCritical Error:No Executable Code Found";
}
}
cout<<RESET;
}
