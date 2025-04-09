package inet.applications.ethernet;
import inet.applications.contract.ICustomIOApp;

simple GooseSemanticAttackerApp like ICustomIOApp
{
    parameters:
        @display("i=block/app");
    gates:
        input in1;
        output out1;
        
        input in2;
        output out2;
}
