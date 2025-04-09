#include "iec_byte_utils.h"

namespace inet {

std::vector<unsigned char> get_bytes(int num, unsigned int len) {
    std::vector<unsigned char> vec(len);
    for (unsigned int i = 0; i < len; ++i) {
        vec[i] = (num >> (8 * (len - i - 1))) & 0xFF;
    }
    return vec;
}

void set_num(unsigned char* c, int num, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i) {
        c[i] = (num >> (8 * (len - i - 1))) & 0xFF;
    }
}

int get_num(unsigned char* c, unsigned int len) {
    int result = 0x0;

    for (int i=0; i<len; i++) {
        result = (result << 8) | c[i];
    }

    return result;
}

int get_byte_count(int num) {
    // If the number is 0, it still requires 1 byte to represent
    if (num == 0) return 1;

    // Calculate the number of bits required to represent the integer
    int bits = static_cast<int>(log2(abs(num))) + 1;

    // Calculate the number of bytes required
    int bytes = bits / 8;
    if (bits % 8 != 0) bytes++; // If the number of bits is not a multiple of 8, we need an extra byte

    return bytes;
}

float INET_API get_float(unsigned char* c, unsigned int len) {
    uint32_t temp =
        (uint32_t(c[0]) << 24) |
        (uint32_t(c[1]) << 16) |
        (uint32_t(c[2]) << 8)  |
        (uint32_t(c[3]));

    float result;
    std::memcpy(&result, &temp, sizeof(result));
    return result;
}

void INET_API set_float(unsigned char* c, float f, unsigned int len) {
    uint32_t temp;
    std::memcpy(&temp, &f, sizeof(temp));


    c[0] = static_cast<unsigned char>((temp >> 24) & 0xFF);
    c[1] = static_cast<unsigned char>((temp >> 16) & 0xFF);
    c[2] = static_cast<unsigned char>((temp >> 8) & 0xFF);
    c[3] = static_cast<unsigned char>(temp & 0xFF);
}


}
