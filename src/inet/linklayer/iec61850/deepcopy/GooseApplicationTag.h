#ifndef __INET_GOOSEAPPLICATIONTAG_H
#define __INET_GOOSEAPPLICATIONTAG_H

#include "inet/common/INETDefs.h"

namespace inet {
class INET_API GooseApplicationTag {
private:
    unsigned char tag; // always 0x61
    std::vector<unsigned char> length_bytes;
    int length;
public:
    GooseApplicationTag(unsigned char* payload);
    ~GooseApplicationTag();

    int size();
    int get_length();

    void set_length_bytes(int length_value);

    std::vector<unsigned char> get_payload();
};
} // namespace inet

#endif // __INET_GOOSEPDUFIELD_H
