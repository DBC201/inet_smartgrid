package inet.applications.ethernet;

simple UdpEncapsulatorApp
{
    parameters:
        @display("i=block/app");
        string source_address = default("");
        string destination_address;
        int source_port = default(-1);
        int destination_port;
        bool encapsulate = default(true);
        bool decapsulate = default(true);
    gates:
        input ethernetIn;
        output ethernetOut;
        
        input socketIn;
        output socketOut;
}

