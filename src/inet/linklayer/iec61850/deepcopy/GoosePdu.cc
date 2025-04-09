#include "GoosePdu.h"
#include "inet/linklayer/iec61850/iec_byte_utils.h"

namespace inet {

GoosePdu::GoosePdu(unsigned char* payload) {
    std::memcpy(appid, payload, 2);
    payload += 2;

    std::memcpy(length, payload, 2);
    payload += 2;

    std::memcpy(reserved1, payload, 2);
    payload += 2;

    std::memcpy(reserved2, payload, 2);
    payload += 2;

    gooseApplicationTag = new GooseApplicationTag(payload);
    payload += gooseApplicationTag->size();

    gocbRef = new BerField(payload);
    payload += gocbRef->size();

    timeAllowedToLive = new BerField(payload);
    payload += timeAllowedToLive->size();

    datset = new BerField(payload);
    payload += datset->size();

    goID = new BerField(payload);
    payload += goID->size();

    t = new BerField(payload);
    payload += t->size();

    stNum = new BerField(payload);
    payload += stNum->size();

    sqNum = new BerField(payload);
    payload += sqNum->size();

    simulation = new BerField(payload);
    payload += simulation->size();

    confRev = new BerField(payload);
    payload += confRev->size();

    ndsCom = new BerField(payload);
    payload += ndsCom->size();

    numDataSetEntries = new BerField(payload);
    payload += numDataSetEntries->size();

    allData = new BerField(payload);
}

int GoosePdu::getStNum() {
    std::vector<unsigned char> &data = stNum->get_data();
    return get_num(data.data(), data.size());
}

int GoosePdu::getSqNum() {
    std::vector<unsigned char> &data = stNum->get_data();
    return get_num(data.data(), data.size());
}

void GoosePdu::setStAndSqNum(int stNum, int sqNum) {
    int oldStNumSize = this->stNum->size();
    int oldSqNumSize = this->sqNum->size();

    auto stNumBytes = get_bytes(stNum, get_byte_count(stNum));
    auto sqNumBytes = get_bytes(stNum, get_byte_count(sqNum));

    this->stNum->set_data(stNumBytes);
    this->sqNum->set_data(sqNumBytes);

    int newStNumSize = this->stNum->size();
    int newSqNumSize = this->sqNum->size();

    int size_change = (oldStNumSize + oldSqNumSize) - (newStNumSize + newSqNumSize);

    if (size_change == 0) {
        return;
    }

    gooseApplicationTag->set_length_bytes(gooseApplicationTag->get_length() + size_change);

    set_num(length, size(), 2);
}

int GoosePdu::getLength() {
    return get_num(length, 2);
}

int GoosePdu::size() {
    return 2 + 2 + 2 + 2 + gooseApplicationTag->size() +
            gocbRef->size() + timeAllowedToLive->size() + datset->size()
                + goID->size() + t->size() + stNum->size() + sqNum->size() + simulation->size()
                + confRev->size() + ndsCom->size() + numDataSetEntries->size() + allData->size();
}

std::vector<unsigned char> GoosePdu::get_payload() {
    std::vector<unsigned char> payload(size());
    int i = 0;

    std::copy(appid, appid + 2, payload.begin() + i);
    i += 2;

    std::copy(length, length + 2, payload.begin() + i);
    i += 2;

    std::copy(reserved1, reserved1 + 2, payload.begin() + i);
    i += 2;

    std::copy(reserved2, reserved2 + 2, payload.begin() + i);
    i += 2;

    std::copy(gooseApplicationTag->get_payload().begin(), gooseApplicationTag->get_payload().end(), payload.begin() + i);
    i += gooseApplicationTag->size();

    std::copy(gocbRef->get_payload().begin(), gocbRef->get_payload().end(), payload.begin() + i);
    i += gocbRef->size();

    std::copy(timeAllowedToLive->get_payload().begin(), timeAllowedToLive->get_payload().end(), payload.begin() + i);
    i += timeAllowedToLive->size();

    std::copy(datset->get_payload().begin(), datset->get_payload().end(), payload.begin() + i);
    i += datset->size();

    std::copy(goID->get_payload().begin(), goID->get_payload().end(), payload.begin() + i);
    i += goID->size();

    std::copy(t->get_payload().begin(), t->get_payload().end(), payload.begin() + i);
    i += t->size();

    std::copy(stNum->get_payload().begin(), stNum->get_payload().end(), payload.begin() + i);
    i += stNum->size();

    std::copy(sqNum->get_payload().begin(), sqNum->get_payload().end(), payload.begin() + i);
    i += sqNum->size();

    std::copy(simulation->get_payload().begin(), simulation->get_payload().end(), payload.begin() + i);
    i += simulation->size();

    std::copy(confRev->get_payload().begin(), confRev->get_payload().end(), payload.begin() + i);
    i += confRev->size();

    std::copy(ndsCom->get_payload().begin(), ndsCom->get_payload().end(), payload.begin() + i);
    i += ndsCom->size();

    std::copy(numDataSetEntries->get_payload().begin(), numDataSetEntries->get_payload().end(), payload.begin() + i);
    i += numDataSetEntries->size();

    std::copy(allData->get_payload().begin(), allData->get_payload().end(), payload.begin() + i);
    i += allData->size();

    return payload;
}


BerField* GoosePdu::get_allData() {
    return allData;
}

GoosePdu::~GoosePdu() {
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
