#ifndef __INET_SVPDUPARSER_H
#define __INET_SVPDUPARSER_H

#include "BerFieldParser.h"
#include "iec_byte_utils.h"
#include "inet/common/INETDefs.h"

namespace inet {
class INET_API SvPduParser {
private:
    unsigned char *appid;
    unsigned char *length;
    unsigned char *reserved1;
    unsigned char *reserved2;

    BerFieldParser* savPdu;
    BerFieldParser* seqASDU;

    BerFieldParser* getChildBER(BerFieldParser* parent, unsigned char tag);
public:
    SvPduParser(unsigned char* payload);

    float get_smpCnt();
    void set_smpCnt(int smpCnt);

    void modifyseqData();

    ~SvPduParser();
};
}

#endif
