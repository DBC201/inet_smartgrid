#include <cstring>

#include "BerField.h"
#include "inet/linklayer/iec61850/iec_byte_utils.h"

namespace inet {

BerField::BerField(unsigned char* payload) {
    tag = *payload;

    unsigned char first_byte = payload[1];

    int length_bytes_size, data_size;

    if (first_byte >> 7 == 0x01) {
        length_bytes_size = (first_byte ^ 0x80) + 1;
        data_size = get_num(&payload[2], length_bytes_size);
    }
    else {
        length_bytes_size = 1;
        data_size = get_num(&payload[1], length_bytes_size);
    }

    length_bytes = std::vector<unsigned char>(payload + 1, payload + 1 + length_bytes_size);

    data = std::vector<unsigned char>(payload + 1 + length_bytes_size, payload + 1 + length_bytes_size + data_size);
}

BerField::~BerField() {
}

unsigned char BerField::get_tag() {
    return tag;
}

int BerField::size() {
    return data.size() + length_bytes.size() + 1;
}

std::vector<unsigned char>& BerField::get_data() {
    return data;
}

void BerField::set_data(std::vector<unsigned char>& new_data) {
    data = new_data;
    unsigned int value = data.size();

    if (value < 0x80) {
        // Short form: one length byte represents the value directly.
        length_bytes.resize(1);
        length_bytes[0] = static_cast<unsigned char>(value);
    } else {
        // Long form: first byte indicates the number of subsequent length bytes.
        int num_bytes = 0;
        unsigned int temp = value;
        while (temp > 0) {
            num_bytes++;
            temp >>= 8;
        }
        length_bytes.resize(num_bytes + 1);
        // First byte: set the MSB and include the number of following bytes.
        length_bytes[0] = static_cast<unsigned char>(0x80 | num_bytes);

        // Fill in the length in big-endian order.
        for (int i = num_bytes; i > 0; i--) {
            length_bytes[i] = static_cast<unsigned char>(value & 0xFF);
            value >>= 8;
        }
    }
}


std::vector<unsigned char> BerField::get_payload() {
    std::vector<unsigned char> payload(size());
    payload[0] = tag;
    std::copy(length_bytes.begin(), length_bytes.end(), payload.begin() + 1);
    std::copy(data.begin(), data.end(), payload.begin() + 1 + length_bytes.size());
    return data;
}

} // namespace inet
