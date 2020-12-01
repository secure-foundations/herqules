`include "platform_if.vh"

module server_wrapper (
    input logic clk,
    input logic rst,

    server_interface.svr srv,

    input logic [63:0] setWr_addr,

    input t_if_ccip_c1_Rx c1_sRx,
    input c1TxAlmFull,
    output t_if_ccip_c1_Tx c1_sTx
);

  // Channel 0 (Memory and MMIO reads)
  wire c0valid;
  wire [13:0] rd_mdata;
  wire [63:0] rd_addr;

  // Channel 1 (Memory writes)
  wire c1valid;
  wire [13:0] wr_mdata;
  wire [63:0] wr_addr;
  wire [511:0] wr_data;
  t_ccip_c1_ReqMemHdr wr_hdr;

  always_comb begin
    wr_hdr = t_ccip_c1_ReqMemHdr'(0);
    wr_hdr.req_type = eREQ_WRPUSH_I;
    wr_hdr.address = t_ccip_clAddr'(wr_addr);
    wr_hdr.vc_sel = eVC_VA;
    wr_hdr.cl_len = eCL_LEN_1;
    wr_hdr.mdata = t_ccip_mdata'(wr_mdata);
    wr_hdr.sop = 1'b1;
  end

  always_ff @(posedge clk) begin
    if (rst) begin
      c1_sTx.hdr <= '0;
      c1_sTx.valid <= 0;
    end else begin
      c1_sTx.valid <= c1valid;
      c1_sTx.hdr <= wr_hdr;
      c1_sTx.data <= t_ccip_clData'(wr_data);
      if (c1valid)
        $display("CCI-P C1 TX: addr %x, mdata %x, data %x", wr_hdr.address, wr_hdr.mdata, wr_data);

      if (c1_sRx.rspValid)
        $display(
            "CCI-P C1 RX: vc_used %x, hit_miss %x, format %x, cl_num %x, resp_type %x, mdata %x",
                c1_sRx.hdr.vc_used, c1_sRx.hdr.hit_miss, c1_sRx.hdr.format, c1_sRx.hdr.cl_num,
                c1_sRx.hdr.resp_type, c1_sRx.hdr.mdata);
    end
  end

  server server (
      .CLK(clk),
      .RST_N(~rst),
      .top_rdReqAddr(rd_addr),
      .top_rdReqMdata(rd_mdata),
      .top_rdReqEN(c0valid),
      .top_rdReqSent_b(1'b0),
      .top_rdRspMdata_m('0),
      .top_rdRspData_d('0),
      .top_rdRspValid_b(1'b0),
      .top_wrReqAddr(wr_addr),
      .top_wrReqMdata(wr_mdata),
      .top_wrReqData(wr_data),
      .top_wrReqEN(c1valid),
      .top_wrReqSent_b(!c1TxAlmFull),
      .top_wrRspMdata_m(c1_sRx.hdr.mdata[13:0]),
      .top_wrRspValid_b(c1_sRx.rspValid),
      .writeMB_0_txFull(srv.txFull),
      .writeMB_0_tx_msg(srv.txP.tx_msg),
      .EN_writeMB_0_tx(srv.txP.tx),
      .writeMB_0_rxEmpty(srv.rxP.rxEmpty),
      .EN_writeMB_0_rxPop(srv.rxPop),
      .writeMB_0_rx_msg(srv.rxP.rx_msg),
      .setRd_addr('0),
      .setWr_addr(setWr_addr)
  );

endmodule
