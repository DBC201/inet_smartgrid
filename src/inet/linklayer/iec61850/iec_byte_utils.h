#ifndef __INET_IEC_BYTE_UTILS_H
#define __INET_IEC_BYTE_UTILS_H

#include "inet/common/INETDefs.h"


namespace inet {
std::vector<unsigned char> INET_API get_bytes(int num, unsigned int len);

void INET_API set_num(unsigned char* c, int num, unsigned int len);

int INET_API get_num(unsigned char* c, unsigned int len);

float INET_API get_float(unsigned char* c, unsigned int len);

void INET_API set_float(unsigned char* c, float f, unsigned int len);

int INET_API get_byte_count(int num);
}

#endif
