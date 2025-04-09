#include <cstring>

#include "BerFieldParser.h"
#include "iec_byte_utils.h"

namespace inet {

BerFieldParser::BerFieldParser(unsigned char* payload) {
    tag = payload;

    unsigned char first_byte = payload[1];

    if (first_byte >> 7 == 0x01) {
        length_bytes_size = (first_byte ^ 0x80) + 1;
        data_size = get_num(&payload[2], length_bytes_size);
    }
    else {
        length_bytes_size = 1;
        data_size = get_num(&payload[1], length_bytes_size);
    }

    data = payload + 1 + length_bytes_size;
}

BerFieldParser::~BerFieldParser() {
}

int BerFieldParser::get_data_size() {
    return data_size;
}

int BerFieldParser::size() {
    return data_size + length_bytes_size + 1;
}

unsigned char* BerFieldParser::get_data() {
    return data;
}

unsigned char* BerFieldParser::get_tag() {
    return tag;
}

} // namespace inet
