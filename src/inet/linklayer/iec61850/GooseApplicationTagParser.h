#ifndef __INET_GOOSEAPPLICATIONTAGPARSER_H
#define __INET_GOOSEAPPLICATIONTAGPARSER_H

#include "inet/common/INETDefs.h"

namespace inet {
class INET_API GooseApplicationTagParser {
private:
    unsigned char* tag; // always 0x61
    unsigned char* length_bytes;
    int length_bytes_size;
public:
    GooseApplicationTagParser(unsigned char* payload);
    ~GooseApplicationTagParser();

    int size();
};
} // namespace inet

#endif // __INET_GOOSEAPPLICATIONTAGPARSER_H
