package inet.applications.contract;

moduleinterface ICustomIOApp
{
    parameters:
        @display("i=block/app");
    gates:
        input in1;
        output out1;
        
        input in2;
        output out2;
}
