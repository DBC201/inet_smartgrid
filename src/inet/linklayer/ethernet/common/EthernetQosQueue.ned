//
// Copyright (C) 2012 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Modifications by Deniz Cakiroglu on Apr 9, 2025
// 
// - Added EthernetGooseQueue module
// Changes can be seen in: https://github.com/DBC201/inet_smartgrid/commit/6a1498400414ef1ced42d532f785d0464aa79c7a
// and https://github.com/DBC201/inet_smartgrid/commit/9bade6df398ebccee6bdc468ea1f480a1bf1a863
//


package inet.linklayer.ethernet.common;

import inet.queueing.contract.IPacketClassifier;
import inet.queueing.contract.IPacketQueue;
import inet.queueing.contract.IPacketScheduler;
import inet.queueing.filter.RedDropper;
import inet.queueing.queue.CompoundPacketQueueBase;
import inet.queueing.queue.DropTailQueue;
import inet.queueing.sink.PassivePacketSink;

//
// Queue module that gives the PAUSE frames a higher priority.
//
//# TODO rename to EthernetQosQueue or keep name as it is?
module EthernetQueue extends DropTailQueue
{
    parameters:
        comparatorClass = default("inet::EthernetFrameTypeComparator");
}

//
// Queue module that gives the PAUSE frames a higher priority,
// and can be parametrized with an ~IPacketQueue for serving the
// data frames.
//
//# TODO rename to CompoundEtherQueue? or CompoundEtherQosQueue?
module EthernetQosQueue extends CompoundPacketQueueBase like IPacketQueue
{
    parameters:
        @display("i=block/queue");
    submodules:
        classifier: <default("EthernetFrameClassifier")> like IPacketClassifier {
            parameters:
                @display("p=100,200");
        }
        pauseQueue: <default("DropTailQueue")> like IPacketQueue {
            parameters:
                @display("p=250,100");
        }
        dataQueue: <default("DropTailQueue")> like IPacketQueue {
            parameters:
                @display("p=250,300;q=l2queue");
        }
        scheduler: <default("PriorityScheduler")> like IPacketScheduler {
            parameters:
                @display("p=400,200");
        }
    connections:
        in --> classifier.in;
        classifier.out++ --> pauseQueue.in;
        classifier.out++ --> dataQueue.in;
        pauseQueue.out --> scheduler.in++;
        dataQueue.out --> scheduler.in++;
        scheduler.out --> out;
}

//
// Queue module that gives the PAUSE frames a higher priority,
// and using Random Early Detection algorithm on data frames,
// and can be parametrized with an ~IPacketQueue for serving the
// data frames.
//
module EthernetQosRedQueue extends CompoundPacketQueueBase like IPacketQueue
{
    parameters:
        @display("i=block/queue");
    submodules:
        classifier: <default("EthernetFrameClassifier")> like IPacketClassifier {
            parameters:
                @display("p=100,200");
        }
        pauseQueue: <default("DropTailQueue")> like IPacketQueue {
            parameters:
                @display("p=250,100");
        }
        redFilter: RedDropper {
            @display("p=190,300");
        }
        dataQueue: <default("DropTailQueue")> like IPacketQueue {
            parameters:
                @display("p=310,300;q=l2queue");
        }
        scheduler: <default("PriorityScheduler")> like IPacketScheduler {
            parameters:
                @display("p=400,200");
        }
    connections:
        in --> classifier.in;
        classifier.out++ --> pauseQueue.in;
        classifier.out++ --> redFilter.in;
        pauseQueue.out --> scheduler.in++;
        dataQueue.out --> scheduler.in++;
        scheduler.out --> out;
        redFilter.out --> dataQueue.in;
}

module EthernetGooseQueue extends CompoundPacketQueueBase like IPacketQueue
{
    @display("bgb=348.97498,246.67499");
    submodules:
        classifier: EthernetGooseClassifier {
            @display("p=53.625,128.7");
        }
        queue: <default("DropTailQueue")> like IPacketQueue {
            parameters:
                @display("p=270,76;q=l2queue");
        }
        dropper: PassivePacketSink {
            @display("p=224.4,160.875");
        }
    connections allowunconnected:
        in --> classifier.in;
        classifier.out++ --> dropper.in;
        classifier.out++ --> queue.in;
        queue.out --> out;
}
