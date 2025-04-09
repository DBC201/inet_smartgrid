#include <cstring>
#include "GooseApplicationTagParser.h"

namespace inet {

GooseApplicationTagParser::GooseApplicationTagParser(unsigned char* payload) {
    tag = payload;
    unsigned char first_byte = payload[1];

    if (first_byte >> 7 == 0x01) {
        length_bytes_size = (first_byte ^ 0x80) + 1;
    }
    else {
        length_bytes_size = 1;
    }

    length_bytes = payload + 1 + length_bytes_size;
}

int GooseApplicationTagParser::size() {
    return 1 + length_bytes_size;
}

GooseApplicationTagParser::~GooseApplicationTagParser() {
}

} // namespace inet
