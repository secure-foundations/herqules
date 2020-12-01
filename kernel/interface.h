#ifndef _HQ_INTERFACE_H_
#define _HQ_INTERFACE_H_

#include "interfaces.h"
#include "verifier.h"

#define INTERFACE_NUM_DEVICES 1

/* Declared functions */
int interface_register(void);
void interface_unregister(void);
#endif /* _HQ_INTERFACE_H_ */
