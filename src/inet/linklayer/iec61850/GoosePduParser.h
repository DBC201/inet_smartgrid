#ifndef __INET_GOOSEPDUPARSER_H
#define __INET_GOOSEPDUPARSER_H

#include "BerFieldParser.h"
#include "inet/common/INETDefs.h"
#include "GooseApplicationTagParser.h"

namespace inet {
class INET_API GoosePduParser {
private:

    // these are all 2 bytes
    unsigned char* appid;
    unsigned char* length;
    unsigned char* reserved1;
    unsigned char* reserved2;

    GooseApplicationTagParser* gooseApplicationTag;

    BerFieldParser* gocbRef; // 0x80
    BerFieldParser* timeAllowedToLive; // 0x81
    BerFieldParser* datset; // 0x82
    BerFieldParser* goID; // 0x83
    BerFieldParser* t; // 0x84
    BerFieldParser* stNum; // 0x85
    BerFieldParser* sqNum; // 0x86
    BerFieldParser* simulation; // 0x87
    BerFieldParser* confRev; // 0x88
    BerFieldParser* ndsCom; // 0x89
    BerFieldParser* numDataSetEntries; // 0x8a

    BerFieldParser* allData; // 0xab
public:
    GoosePduParser(unsigned char* payload);
    ~GoosePduParser();

    int size();

    int getLength();
    int getStNum();
    int getSqNum();
    unsigned char getBoolean();


    void setStNum(int stNum);
    void setSqNum(int sqNum);

    BerFieldParser* get_allData();
};
} // namespace inet

#endif // __INET_GOOSEPDUPARSER_H
