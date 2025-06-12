#include "SvPduParser.h"

namespace inet {
SvPduParser::SvPduParser(unsigned char* payload) {
    appid = payload;
    payload += 2;

    length = payload;
    payload += 2;

    reserved1 = payload;
    payload += 2;

    reserved2 = payload;
    payload += 2;

    savPdu = new BerFieldParser(payload);

    seqASDU = getChildBER(savPdu, 0xa2);
}

void SvPduParser::modifyseqData() {
    BerFieldParser* ASDU = getChildBER(seqASDU, 0x30);
    BerFieldParser* seqData = getChildBER(ASDU, 0x87);
    delete ASDU;

    float f = get_float(seqData->get_data(), 4);
    f *= 10;
    set_float(seqData->get_data(), f, 4);

    delete seqData;
}

BerFieldParser* SvPduParser::getChildBER(BerFieldParser* parent, unsigned char tag) {
    unsigned char* parent_data = parent->get_data();
    int parent_size = parent->get_data_size();

    BerFieldParser* result = nullptr;

    int i = 0;

    while (i < parent_size) {
        BerFieldParser* child = new BerFieldParser(parent_data + i);

        unsigned char child_tag = *(child->get_tag());
        if (child_tag == tag) {
            result = child;
            break;
        }

        i += child->size();
        delete child;
    }

    return result;
}

void SvPduParser::set_smpCnt(int smpCnt) {
    BerFieldParser* ASDU = getChildBER(seqASDU, 0x30);
    BerFieldParser* smpCntField = getChildBER(ASDU, 0x82);
    delete ASDU;
    unsigned char* m_smpCnt = smpCntField->get_data();
    delete smpCntField;
    set_num(m_smpCnt, smpCnt, 2);
}

float SvPduParser::get_smpCnt() {
    BerFieldParser* ASDU = getChildBER(seqASDU, 0x30);
    BerFieldParser* smpCntField = getChildBER(ASDU, 0x82);
    delete ASDU;
    unsigned char* m_smpCnt = smpCntField->get_data();
    delete smpCntField;
    return get_num(m_smpCnt, 2);
}

SvPduParser::~SvPduParser() {
    delete savPdu;
    delete seqASDU;
}

};

