#ifndef __INET_BERFIELD_H
#define __INET_BERFIELD_H

#include "inet/common/INETDefs.h"

namespace inet {
class INET_API BerField {
private:
    unsigned char tag; // always 1 byte

    std::vector<unsigned char> length_bytes;
    std::vector<unsigned char> data;
public:
    BerField(unsigned char* payload);
    ~BerField();
    unsigned char get_tag();

    int size();

    std::vector<unsigned char>& get_data();
    void set_data(std::vector<unsigned char>& data);

    std::vector<unsigned char> get_payload();
};
} // namespace inet

#endif // __INET_BERFIELD_H
