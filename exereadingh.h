#ifndef reading22
#define reading22
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
vector <unsigned char> lib;
///////////////////
//RVA FUNCTION 
int rva_offest(int rva,int* sectable);
/////////////////

int impt_libraries_num;
int rtr;
int reading();
};

#endif