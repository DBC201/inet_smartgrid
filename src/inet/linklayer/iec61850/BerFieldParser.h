#ifndef __INET_BERFIELDPARSER_H
#define __INET_BERFIELDPARSER_H

#include "inet/common/INETDefs.h"

namespace inet {
class INET_API BerFieldParser {
private:
    unsigned char* tag; // always 1 byte

    int length_bytes_size;
    int data_size;

    unsigned char* data;
public:
    BerFieldParser(unsigned char* payload);
    ~BerFieldParser();

    int size();

    int get_data_size();
    unsigned char* get_data();

    unsigned char* get_tag();
};
} // namespace inet

#endif // __INET_BERFIELDPARSER_H
