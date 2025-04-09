#include "GoosePduParser.h"
#include "iec_byte_utils.h"
#include <queue>

namespace inet {

GoosePduParser::GoosePduParser(unsigned char* payload) {
    appid = payload;
    payload += 2;

    length = payload;
    payload += 2;

    reserved1 = payload;
    payload += 2;

    reserved2 = payload;
    payload += 2;

    gooseApplicationTag = new GooseApplicationTagParser(payload);
    payload += gooseApplicationTag->size();

    gocbRef = new BerFieldParser(payload);
    payload += gocbRef->size();

    timeAllowedToLive = new BerFieldParser(payload);
    payload += timeAllowedToLive->size();

    datset = new BerFieldParser(payload);
    payload += datset->size();

    goID = new BerFieldParser(payload);
    payload += goID->size();

    t = new BerFieldParser(payload);
    payload += t->size();

    stNum = new BerFieldParser(payload);
    payload += stNum->size();

    sqNum = new BerFieldParser(payload);
    payload += sqNum->size();

    simulation = new BerFieldParser(payload);
    payload += simulation->size();

    confRev = new BerFieldParser(payload);
    payload += confRev->size();

    ndsCom = new BerFieldParser(payload);
    payload += ndsCom->size();

    numDataSetEntries = new BerFieldParser(payload);
    payload += numDataSetEntries->size();

    allData = new BerFieldParser(payload);
}

int GoosePduParser::getStNum() {
    return get_num(stNum->get_data(), stNum->get_data_size());
}

int GoosePduParser::getSqNum() {
    return get_num(sqNum->get_data(), sqNum->get_data_size());
}

unsigned char GoosePduParser::getBoolean() {
    std::queue<BerFieldParser*> q;

    unsigned char returnVal = 0xFF;

    q.push(allData);

    while (!q.empty()) {
        BerFieldParser* currField = q.front();
        q.pop();

        unsigned char tag = *(currField->get_tag());

        if (tag == 0x83) { // boolean
            returnVal = currField->get_data()[0];
        } else if (tag == 0xa2 || tag == 0xab) { // sub field (0x2a) or allData (0xab)
            int i = 0;

            while (i < currField->get_data_size()) {
                BerFieldParser* next = new BerFieldParser(currField->get_data() + i);

                q.push(next);

                i += next->size();
            }
        }

        if (currField != allData) {
            delete currField;
        }
    }

    return returnVal;
}

void GoosePduParser::setStNum(int stNum) {
    // TODO: HANDLE OVERFLOW
    set_num(this->stNum->get_data(), stNum, this->stNum->get_data_size());
}

void GoosePduParser::setSqNum(int sqNum) {
    // TODO: HANDLE OVERFLOW
    set_num(this->sqNum->get_data(), sqNum, this->sqNum->get_data_size());
}

int GoosePduParser::getLength() {
    return get_num(length, 2);
}

int GoosePduParser::size() {
    return 2 + 2 + 2 + 2 + gooseApplicationTag->size() +
            gocbRef->size() + timeAllowedToLive->size() + datset->size()
                + goID->size() + t->size() + stNum->size() + sqNum->size() + simulation->size()
                + confRev->size() + ndsCom->size() + numDataSetEntries->size() + allData->size();
}


BerFieldParser* GoosePduParser::get_allData() {
    return allData;
}

GoosePduParser::~GoosePduParser() {
    delete gooseApplicationTag;
    delete gocbRef;
    delete timeAllowedToLive;
    delete datset;
    delete goID;
    delete t;
    delete stNum;
    delete sqNum;
    delete simulation;
    delete confRev;
    delete ndsCom;
    delete numDataSetEntries;
    delete allData;
}

} // namespace inet
