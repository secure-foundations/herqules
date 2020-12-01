`include "platform_if.vh"

`include "hq_fifo_csr.vh"

module hq_fifo (
    input logic clk,
    input logic rst,

    // Connections toward the server
    server_interface.clt srv,

    input logic [255:0] wr_msg,
    input logic wr_valid,

    input logic [63:0] wr_capacity,
    output logic [63:0] wr_drops
);

  logic [63:0] counter, offset;

  always_ff @(posedge clk) begin
    if (rst) begin
      srv.txP.tx <= '0;
      wr_drops <= '0;

      counter <= 64'h1;
      offset <= '0;
    end else begin
      srv.txP.tx <= wr_valid && !srv.txFull;
      if (wr_valid && !srv.txFull) begin
        srv.txP.tx_msg.head.srcid <= '0;
        srv.txP.tx_msg.head.dstid <= '0;
        srv.txP.tx_msg.head.arg0 <= '0;
        srv.txP.tx_msg.head.arg1 <= offset[31:0];
        srv.txP.tx_msg.head.arg2 <= offset[63:32];
        srv.txP.tx_msg.head.arg3 <= '0;
        // Must keep in sync with 'registers.h'
        srv.txP.tx_msg.data <= {MSG_CONSTANT, counter, offset, 64'h0, wr_msg};

        // Increment the counter and write offset
        counter <= counter + 64'h1;
        offset <= ((offset + 64'h1) < wr_capacity) ? offset + 64'h1 : 64'h0;
        $strobe("TX: counter %x, offset %x, capacity %x, wr_msg %x", counter, offset, wr_capacity, srv.txP.tx_msg.data);
      end else if (wr_valid && srv.txFull) begin
        wr_drops <= wr_drops + 64'h1;
        $fatal("FIFO TX: Dropping message: %x!", wr_msg);
      end
    end
  end

  // Pop messages while channel is not empty
  assign srv.rxPop = !srv.rxP.rxEmpty;

endmodule
