#include "GooseApplicationTag.h"
#include "inet/linklayer/iec61850/iec_byte_utils.h"
#include <cstring>

namespace inet {

GooseApplicationTag::GooseApplicationTag(unsigned char* payload) {
    tag = *payload;
    unsigned char first_byte = payload[1];

    int length_bytes_size;

    if (first_byte >> 7 == 0x01) {
        length_bytes_size = (first_byte ^ 0x80) + 1;
    }
    else {
        length_bytes_size = 1;
    }


    length = get_num(payload + 1, length_bytes_size);
    length_bytes = std::vector<unsigned char>(payload + 1, payload + 1 + length_bytes_size);
}

int GooseApplicationTag::size() {
    return 1 + length_bytes.size();
}

int GooseApplicationTag::get_length() {
    return length;
}

std::vector<unsigned char> GooseApplicationTag::get_payload() {
    std::vector<unsigned char> payload(size());
    payload[0] = tag;
    std::copy(length_bytes.begin(), length_bytes.end(), payload.begin() + 1);
    return payload;
}

void GooseApplicationTag::set_length_bytes(int length_value) {
    if (length_value < 0x80) {
        // Short form: one length byte represents the value directly.
        length_bytes.resize(1);
        length_bytes[0] = static_cast<unsigned char>(length_value);
    } else {
        // Long form: first byte indicates the number of subsequent length bytes.
        int num_bytes = 0;
        int temp = length_value;
        while (temp > 0) {
            num_bytes++;
            temp >>= 8;
        }
        length_bytes.resize(num_bytes + 1);
        // First byte: MSB is set and lower 7 bits are the count of length bytes.
        length_bytes[0] = static_cast<unsigned char>(0x80 | num_bytes);

        // Fill in the length in big-endian order.
        for (int i = num_bytes; i > 0; i--) {
            length_bytes[i] = static_cast<unsigned char>(length_value & 0xFF);
            length_value >>= 8;
        }
    }
    length = length_value;
}

GooseApplicationTag::~GooseApplicationTag() {
}

} // namespace inet
