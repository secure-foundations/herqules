`include "platform_if.vh"
`include "afu_json_info.vh"

`include "hq_fifo_csr.vh"

module hq_fifo_csr (
    input clk,
    input rst,

    // CCI-P signals
    input t_if_ccip_c0_Rx c0_sRx,
    input logic c0TxAlmFull,
    output t_if_ccip_c0_Tx c0_sTx,
    output t_if_ccip_c2_Tx c2_sTx,

    output reg [63:0] wr_addr,
    output reg [63:0] wr_capacity,
    output wire [255:0] wr_msg,
    output reg wr_valid,
    input [63:0] wr_drops
);

  function automatic [3:0] getSize(const ref t_ccip_c0_ReqMmioHdr hdr);
    case (hdr.length)
      2'b00: return 4'd1;
      2'b01: return 4'd1;
      2'b10: return 4'd8;
      default: return 4'd0;
    endcase
  endfunction

  // The AFU must respond with its AFU ID in response to MMIO reads of
  // the CCI-P device feature header (DFH).  The AFU ID is a unique ID
  // for a given program.  Here we generated one with the "uuidgen"
  // program and stored it in the AFU's JSON file.  ASE and synthesis
  // setup scripts automatically invoke the OPAE afu_json_mgr script
  // to extract the UUID into afu_json_info.vh.
  logic [127:0] afu_id = `AFU_ACCEL_UUID;

  // The c0 header is normally used for memory read responses.
  // The header must be interpreted as an MMIO response when
  // c0 mmmioRdValid or mmioWrValid is set.  In these cases the
  // c0 header is cast into a ReqMmioHdr.
  t_ccip_c0_ReqMmioHdr mmioHdr;
  assign mmioHdr = t_ccip_c0_ReqMmioHdr'(c0_sRx.hdr);
  logic [3:0] mmioSz;
  assign mmioSz = getSize(mmioHdr);

  // Application variables
  logic [63:0] wr_pid;
  logic [63:0] wr_msg0, wr_msg1, wr_msg2;

  assign wr_msg = {wr_msg2, wr_msg1, wr_msg0, wr_pid};

  // Channel 0 (Memory read and MMIO read/write), channel 2 (MMIO read response)
  always_ff @(posedge clk) begin
    if (rst) begin
      c0_sTx.hdr <= t_ccip_c0_RspMemHdr'(0);
      c0_sTx.valid <= 1'b0;

      c2_sTx.hdr <= t_ccip_c2_RspMmioHdr'(0);
      c2_sTx.mmioRdValid <= 1'b0;

      wr_addr <= '0;
      wr_capacity <= '0;
      wr_valid <= 1'b0;

      wr_pid <= '0;
      wr_msg0 <= '0;
      wr_msg1 <= '0;
      wr_msg2 <= '0;
    end else begin
      // Default to invalid
      c2_sTx.mmioRdValid <= 1'b0;

      // MMIO read
      if (c0_sRx.mmioRdValid) begin
        $display("CCI-P C0 RX MMIO-RD: addr %x, length %d, tid %x", mmioHdr.address, mmioHdr.length,
                 mmioHdr.tid);

        // Copy TID, which the host needs to map the response to the request
        c2_sTx.hdr.tid <= mmioHdr.tid;

        c2_sTx.mmioRdValid <= 1'b1;

        case (mmioHdr.address) inside
          REG_DEV_FEATURE_HDR: c2_sTx.data <= {4'h1,  // feature type = AFU
          8'h0,  // reserved
          4'h0,  // AFU minor revision = 0
          7'b0,  // reserved
          1'h1,  // end of DFH list = 1
          24'h0,  // next DFH offset = 0
          4'h1,  // AFU major version = 1
          12'h0  // feature ID = 0
          };
          REG_AFU_ID_L: c2_sTx.data <= afu_id[63:0];
          REG_AFU_ID_H: c2_sTx.data <= afu_id[127:64];
          REG_DFH_RSVD0: c2_sTx.data <= t_ccip_mmioData'(0);
          REG_DFH_RSVD1: c2_sTx.data <= t_ccip_mmioData'(0);

          REG_MSG_DROPS: c2_sTx.data <= wr_drops;

          REG_HOST_BUF_ADDR: c2_sTx.data <= wr_addr;
          REG_HOST_BUF_SZ: c2_sTx.data <= wr_capacity;
          REG_PID: c2_sTx.data <= wr_pid;
          default: c2_sTx.data <= '0;
        endcase
      end

      // Default to zero
      wr_valid <= 1'b0;

      // MMIO write
      if (c0_sRx.mmioWrValid) begin
        // FIXME: Quartus can't infer that mmioSz has a max of 8, so explicitly
        // guard against the max to prevent out-of-bounds array access
        for (logic [3:0] i = 0; i < 4'd8 && i < mmioSz; ++i) begin
          $display("CCI-P C0 RX MMIO-WR: addr %x, length %d, tid %x", mmioHdr.address + 2 * i,
                   mmioSz, mmioHdr.tid);

          case (mmioHdr.address + 2 * i) inside
            REG_HOST_BUF_ADDR: wr_addr <= c0_sRx.data[64 * i +: 64];
            REG_HOST_BUF_SZ: wr_capacity <= c0_sRx.data[64 * i +: 64];
            REG_PID: wr_pid <= c0_sRx.data[64 * i +: 64];

            REG_MSG0: wr_msg0 <= c0_sRx.data[64 * i +: 64];
            REG_MSG1: wr_msg1 <= c0_sRx.data[64 * i +: 64];
            REG_MSG2: begin
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end

            REG_MSG1_ALIGN: wr_msg1 <= c0_sRx.data[64 * i +: 64];
            REG_MSG2_DEFINE: begin
              wr_msg0 <= CFI_MSG_DEFINE;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_CHECK: begin
              wr_msg0 <= CFI_MSG_CHECK;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_CHECK_INVALIDATE: begin
              wr_msg0 <= CFI_MSG_CHECK_INVALIDATE;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_COPY_BLOCK: begin
              wr_msg0 <= HQ_MSG_COPY_BLOCK;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_INVALIDATE_BLOCK: begin
              wr_msg0 <= HQ_MSG_INVALIDATE_BLOCK;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_MOVE_BLOCK: begin
              wr_msg0 <= HQ_MSG_MOVE_BLOCK;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_SYSCALL: begin
              wr_msg0 <= HQ_MSG_SYSCALL;
              wr_msg1 <= '0;
              wr_msg2 <= '0;
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_INIT_GLOBALS: begin
              wr_msg0 <= CFI_MSG_INIT_GLOBALS;
              wr_msg1 <= '0;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
            REG_MSG2_INVALIDATE: begin
              wr_msg0 <= HQ_MSG_INVALIDATE;
              wr_msg1 <= '0;
              wr_msg2 <= c0_sRx.data[64 * i +: 64];
              if (wr_addr) wr_valid <= 1'b1;
            end
          endcase
        end
      end

      // Memory read response
      if (c0_sRx.rspValid)
        $display("CCI-P C0 RX: vc_used %x, hit_miss %x, cl_num %x, resp_type %x, mdata %x",
                 c0_sRx.hdr.vc_used, c0_sRx.hdr.hit_miss, c0_sRx.hdr.cl_num, c0_sRx.hdr.resp_type,
                 c0_sRx.hdr.mdata);
    end
  end

endmodule
