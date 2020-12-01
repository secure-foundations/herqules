package MessagePack;

import Channels::*;
import CBuffer::*;
import FIFO::*;
import FIFOF::*;
import FIFOFA::*;
import FIFOLevel::*;
import SpecialFIFOs::*;
import Vector::*;

typedef struct
	{
		data 	payload;
	}
	AM_DATA#(type data)
		deriving(Bits,Eq);

typedef struct
	{
		sdarg	srcid;
		sdarg	dstid;
		sdarg	arg0;
		sdarg	arg1;
		sdarg	arg2;
		sdarg	arg3;
	}
	AM_HEAD#(type sdarg)
		deriving(Bits,Eq);

typedef struct
	{
		AM_DATA#(data)	data;
		AM_HEAD#(sdarg) head;
	}
	AM_FULL#(type sdarg, type data)
		deriving(Bits,Eq);

interface Server#(type req_typ, type rsp_typ, numeric type threshold);
	(* prefix="" *) 
	interface TxMsgChannel#(req_typ) txPort;
	(* prefix="" *) 
	interface RxMsgChannel#(rsp_typ) rxPort;
endinterface

module mkReadServer#(RdChannel#(addr,marg,data,thresh,n_out_mem) rdC, addr offset)
										(Server#(AM_FULL#(sdarg,data),AM_FULL#(sdarg,data),threshold))
							provisos(Bits#(marg,a_),
									 Bits#(addr,b_),
									 Bits#(data,c_),
									 Bits#(sdarg,d_),
									 Arith#(sdarg),
									 //Add#(a__, d_, b_),
									 Add#(a__, d_, b_),
									 Log#(threshold, a_),
									 PrimIndex#(marg,g_));
									 //Literal#(data));
	Bool order = True;

	CBuffer#(AM_HEAD#(sdarg),AM_DATA#(data),marg,2,threshold) cBuf; 
	if (order) begin
		cBuf <- mkCompletionBufferBypass;
	end else begin
		cBuf <- mkCompletionBufferU;
	end

	rule get_response(!rdC.rxEmpty);
		marg md = rdC.rxMarg();
		data dd = rdC.rxData();
		let ad = AM_DATA { payload: dd };
		cBuf.complete(md,ad);
		rdC.rxPop();
	endrule

    let tx_ifc = interface TxMsgChannel#(AM_FULL#(sdarg,data));
		method Bool txFull();
			return !cBuf.canReserve() || rdC.txFull();
		endmethod
		method Action tx(AM_FULL#(sdarg,data) r);
			addr a = unpack(extend(pack(r.head.arg1))+pack(offset));
			let tg <- cBuf.reserve(r.head);
			rdC.tx(a,tg);
		endmethod
    endinterface;

    let rx_ifc = interface RxMsgChannel#(AM_FULL#(sdarg,data));
		method Bool rxEmpty();
			return !cBuf.notEmpty();
		endmethod
		method Action rxPop();
			cBuf.deq();
		endmethod
		method AM_FULL#(sdarg,data) rx();
                    let hd = cBuf.firstMeta;
                    sdarg srcid = hd.srcid;
                    hd.srcid = hd.dstid;
                    hd.dstid = srcid;
		    let rsp = AM_FULL { head: hd, data: cBuf.firstData };
			return rsp;
		endmethod
    endinterface;

	interface txPort = tx_ifc;
	interface rxPort = rx_ifc;

endmodule

module mkWriteServer#(WrChannel#(addr,marg,data,thresh,n_out_mem) wrC, addr offset)
										(Server#(AM_FULL#(sdarg,data),AM_FULL#(sdarg,data),threshold))
							provisos(Bits#(marg,a_),
									 Bits#(addr,b_),
									 Bits#(data,c_),
									 Bits#(sdarg,d_),
									 Arith#(sdarg),
									 //Add#(a__, d_, b_),
									 Add#(a__, d_, b_),
									 Log#(threshold, a_),
									 PrimIndex#(marg,g_));
									 //Literal#(data));
	Bool order = True;

	CBuffer#(AM_HEAD#(sdarg),AM_DATA#(data),marg,2,threshold) cBuf; 
	if (order) begin
		cBuf <- mkCompletionBufferBypass;
	end else begin
		cBuf <- mkCompletionBufferU;
	end

	rule get_response(!wrC.rxEmpty);
		marg md = wrC.rxMarg();
		cBuf.complete(md,?);
		wrC.rxPop();
	endrule

    let tx_ifc = interface TxMsgChannel#(AM_FULL#(sdarg,data));
		method Bool txFull();
			return !cBuf.canReserve() || wrC.txFull();
		endmethod
		method Action tx(AM_FULL#(sdarg,data) w);
			addr a = unpack(extend(pack(w.head.arg1))+pack(offset));
			let tg <- cBuf.reserve(w.head);
			wrC.tx(a,tg,w.data.payload);
		endmethod
    endinterface;

    let rx_ifc = interface RxMsgChannel#(AM_FULL#(sdarg,data));
		method Bool rxEmpty();
			return !cBuf.notEmpty();
		endmethod
		method Action rxPop();
			cBuf.deq();
		endmethod
		method AM_FULL#(sdarg,data) rx();
                    let hd = cBuf.firstMeta;
                    sdarg srcid = hd.srcid;
                    hd.srcid = hd.dstid;
                    hd.dstid = srcid;
		    let rsp = AM_FULL { head: hd, data: cBuf.firstData };
			return rsp;
		endmethod
    endinterface;

	interface txPort = tx_ifc;
	interface rxPort = rx_ifc;

endmodule

endpackage