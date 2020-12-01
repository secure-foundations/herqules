#ifndef _HQ_INTERFACES_TX_H_
#define _HQ_INTERFACES_TX_H_

#include "interfaces.h"

#if INTERFACE_TYPE == INTERFACE_TYPE_DPDK
#include "../interfaces/dpdk-tx.h"
using tx_interface = HQ::DPDK::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_MODEL
#include "../interfaces/model.h"
using tx_interface = HQ::MODEL::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_MODEL_SIM
#include "../interfaces/model_sim.h"
using tx_interface = HQ::MODEL_SIM::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_NONE
#include "../interfaces/none.h"
using tx_interface = HQ::NONE::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_OPAE
#include "../interfaces/opae-tx.h"
using tx_interface = HQ::OPAE::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_PAGES
#include "../interfaces/pages.h"
using tx_interface = HQ::PAGES::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
#include "../interfaces/posix_fifo.h"
using tx_interface = HQ::POSIX_FIFO::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
#include "../interfaces/posix_mq.h"
using tx_interface = HQ::POSIX_MQ::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_SHM
#include "../interfaces/posix_shm.h"
using tx_interface = HQ::POSIX_SHM::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_SOCKETS_UNIX
#include "../interfaces/sockets_unix.h"
using tx_interface = HQ::SOCKETS_UNIX::TX;
#elif INTERFACE_TYPE == INTERFACE_TYPE_ZERO
#include "../interfaces/zero.h"
using tx_interface = HQ::ZERO::TX;
#else
#error "Unrecognized interface type!"
#endif /* INTERFACE_TYPE */

#endif /* _HQ_INTERFACES_TX_H_ */
