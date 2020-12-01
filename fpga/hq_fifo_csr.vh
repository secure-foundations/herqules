`ifndef HQ_FIFO_CSR_VH
`define HQ_FIFO_CSR_VH

/* 32-bit address space */
// Must keep in sync with 'registers.h'
localparam t_ccip_mmioAddr REG_DEV_FEATURE_HDR = 'h00;
localparam t_ccip_mmioAddr REG_AFU_ID_L = 'h02;
localparam t_ccip_mmioAddr REG_AFU_ID_H = 'h04;
localparam t_ccip_mmioAddr REG_DFH_RSVD0 = 'h06;
localparam t_ccip_mmioAddr REG_DFH_RSVD1 = 'h08;

localparam t_ccip_mmioAddr REG_MSG_DROPS = 'h0A;

localparam t_ccip_mmioAddr REG_HOST_BUF_ADDR = 'h10;
localparam t_ccip_mmioAddr REG_HOST_BUF_SZ = 'h12;

localparam t_ccip_mmioAddr REG_MSG0 = 'h20;
localparam t_ccip_mmioAddr REG_MSG1 = 'h22;
localparam t_ccip_mmioAddr REG_MSG2 = 'h24;

// Takes two arguments
localparam t_ccip_mmioAddr REG_MSG1_ALIGN = 'h40;
localparam t_ccip_mmioAddr REG_MSG2_DEFINE = 'h48;
localparam t_ccip_mmioAddr REG_MSG2_CHECK = 'h50;
localparam t_ccip_mmioAddr REG_MSG2_CHECK_INVALIDATE = 'h58;
localparam t_ccip_mmioAddr REG_MSG2_COPY_BLOCK = 'h60;
localparam t_ccip_mmioAddr REG_MSG2_INVALIDATE_BLOCK = 'h68;
localparam t_ccip_mmioAddr REG_MSG2_MOVE_BLOCK = 'h70;

// Takes zero arguments
localparam t_ccip_mmioAddr REG_MSG2_SYSCALL = 'h80;
// Takes one argument
localparam t_ccip_mmioAddr REG_MSG2_INIT_GLOBALS = 'h88;
localparam t_ccip_mmioAddr REG_MSG2_INVALIDATE = 'h90;

localparam t_ccip_mmioAddr REG_PID = 'h400;

localparam [63:0] MSG_CONSTANT = 64'hfeedface;

// Must keep in sync with 'messages.h'
enum {
  HQ_MSG_EMPTY,
  HQ_MSG_SYSCALL,
  HQ_MSG_INVALIDATE,
  HQ_MSG_COPY_BLOCK,
  HQ_MSG_INVALIDATE_BLOCK,
  HQ_MSG_MOVE_BLOCK,
  CFI_MSG_DEFINE,
  CFI_MSG_CHECK,
  CFI_MSG_CHECK_INVALIDATE,
  CFI_MSG_INIT_GLOBALS
} t_hq_msg;

`endif
