#ifndef _HQ_INTERFACES_RX_H_
#define _HQ_INTERFACES_RX_H_

#include "interfaces.h"

#if INTERFACE_TYPE == INTERFACE_TYPE_DPDK
#include "../interfaces/dpdk-rx.h"
using rx_interface = HQ::DPDK::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_MODEL
#include "../interfaces/model.h"
using rx_interface = HQ::MODEL::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_MODEL_SIM
#include "../interfaces/model_sim.h"
using rx_interface = HQ::MODEL_SIM::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_NONE
#include "../interfaces/none.h"
using rx_interface = HQ::NONE::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_OPAE
#include "../interfaces/opae-rx.h"
using rx_interface = HQ::OPAE::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_PAGES
#include "../interfaces/pages.h"
using rx_interface = HQ::PAGES::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
#include "../interfaces/posix_fifo.h"
using rx_interface = HQ::POSIX_FIFO::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
#include "../interfaces/posix_mq.h"
using rx_interface = HQ::POSIX_MQ::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_SHM
#include "../interfaces/posix_shm.h"
using rx_interface = HQ::POSIX_SHM::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_SOCKETS_UNIX
#include "../interfaces/sockets_unix.h"
using rx_interface = HQ::SOCKETS_UNIX::RX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_ZERO
#include "../interfaces/zero.h"
using rx_interface = HQ::ZERO::RX;
#else
#error "Unrecognized interface type!"
#endif /* INTERFACE_TYPE */

#endif /* _HQ_INTERFACES_RX_H_ */
