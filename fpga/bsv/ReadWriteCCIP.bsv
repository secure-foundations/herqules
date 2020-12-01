import MessagePack::*;
import Vector::*;
import Channels::*;

interface ReadWriteCCIP;
    interface ChannelsTopHARP#(Bit#(64), Bit#(14), Bit#(512)) topC;
    interface Server#(AM_FULL#(Bit#(64), Bit#(512)), AM_FULL#(Bit#(64), Bit#(512)), 512) read;
    interface Server#(AM_FULL#(Bit#(64), Bit#(512)), AM_FULL#(Bit#(64), Bit#(512)), 512) write;
    (* always_ready, always_enabled, prefix = "" *) method Action setRd_addr_read((* port = "setRd_addr_read" *) Bit#(64) x);
    (* always_ready, always_enabled, prefix = "" *) method Action setWr_addr_write((* port = "setWr_addr_write" *) Bit#(64) x);
endinterface

(* synthesize *)
module mkReadWriteCCIP(ReadWriteCCIP);
    TopConvertHARP#(Bit#(9), Bit#(9), Bit#(64), Bit#(14), Bit#(512), 2, 512) topC_convert <- mkTopConvertHARP();
    RdChannel#(Bit#(64), Bit#(9), Bit#(512), 2, 512) memR_topC = topC_convert.rdch;
    WrChannel#(Bit#(64), Bit#(9), Bit#(512), 2, 512) memW_topC = topC_convert.wrch;

    Reg#(Bit#(64)) regsetRd_addr_read <- mkReg(0);
    Reg#(Bit#(64)) regsetWr_addr_write <- mkReg(0);

    Server#(AM_FULL#(Bit#(64), Bit#(512)), AM_FULL#(Bit#(64), Bit#(512)), 512) srvread <- mkReadServer(memR_topC, truncate(regsetRd_addr_read));

    Server#(AM_FULL#(Bit#(64), Bit#(512)), AM_FULL#(Bit#(64), Bit#(512)), 512) srvwrite <- mkWriteServer(memW_topC, truncate(regsetWr_addr_write));

    interface topC = topC_convert.top;
    interface read = srvread;
    interface write = srvwrite;

    method Action setRd_addr_read(Bit#(64) x);
        regsetRd_addr_read <= x;
    endmethod
    method Action setWr_addr_write(Bit#(64) x);
        regsetWr_addr_write <= x;
    endmethod

endmodule