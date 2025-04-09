#ifndef __INET_GOOSEPDU_H
#define __INET_GOOSEPDU_H

#include "BerField.h"
#include "inet/common/INETDefs.h"
#include "GooseApplicationTag.h"

namespace inet {
class INET_API GoosePdu {
private:

    // these are all 2 bytes
    unsigned char appid[2];
    unsigned char length[2];
    unsigned char reserved1[2];
    unsigned char reserved2[2];

    GooseApplicationTag* gooseApplicationTag;

    BerField* gocbRef; // 0x80
    BerField* timeAllowedToLive; // 0x81
    BerField* datset; // 0x82
    BerField* goID; // 0x83
    BerField* t; // 0x84
    BerField* stNum; // 0x85
    BerField* sqNum; // 0x86
    BerField* simulation; // 0x87
    BerField* confRev; // 0x88
    BerField* ndsCom; // 0x89
    BerField* numDataSetEntries; // 0x8a

    BerField* allData; // 0xab
public:
    GoosePdu(unsigned char* payload);
    ~GoosePdu();

    int size();

    int getLength();
    int getStNum();
    int getSqNum();

    void setStAndSqNum(int stNum, int sqNum);

    std::vector<unsigned char> get_payload();

    BerField* get_allData();
};
} // namespace inet

#endif // __INET_GOOSEPDU_H
