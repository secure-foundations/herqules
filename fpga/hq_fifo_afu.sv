`include "platform_if.vh"

`include "server_interface.vh"

module hq_fifo_afu (
    input clk,  // Core clock. CCI interface is synchronous to this clock.
    input reset,  // CCI interface ACTIVE HIGH reset.

    // CCI-P signals
    input t_if_ccip_Rx cp2af_sRxPort,
    output t_if_ccip_Tx af2cp_sTxPort
);

  wire [63:0] wr_addr;
  wire [63:0] wr_capacity;
  wire [255:0] wr_msg;
  wire wr_valid;
  wire [63:0] wr_drops;

  hq_fifo_csr csr (
      .clk(clk),
      .rst(reset),

      .c0_sRx(cp2af_sRxPort.c0),
      .c0TxAlmFull(cp2af_sRxPort.c0TxAlmFull),
      .c0_sTx(af2cp_sTxPort.c0),
      .c2_sTx(af2cp_sTxPort.c2),

      .wr_addr(wr_addr),
      .wr_capacity(wr_capacity),
      .wr_msg(wr_msg),
      .wr_valid(wr_valid),
      .wr_drops(wr_drops)
  );

  // Interface for interacting with host memory
  server_interface srv_int ();

  // Converts MMIO writes to host memory requests
  hq_fifo fifo (
      .clk(clk),
      .rst(reset),

      .srv(srv_int),

      .wr_msg(wr_msg),
      .wr_valid(wr_valid),

      .wr_capacity(wr_capacity),
      .wr_drops(wr_drops)
  );

  // Handles host memory operations
  server_wrapper server (
      .clk(clk),
      .rst(reset),

      .srv(srv_int),

      .setWr_addr(wr_addr),

      .c1_sRx(cp2af_sRxPort.c1),
      .c1TxAlmFull(cp2af_sRxPort.c1TxAlmFull),
      .c1_sTx(af2cp_sTxPort.c1)
  );

endmodule
