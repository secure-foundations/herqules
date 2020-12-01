#ifndef _HQ_MODULE_H_
#define _HQ_MODULE_H_

#include <linux/rhashtable.h>

#include "hq.h"

/* Exported symbols for other modules */
struct module *hq_get_module(void);

/* Internal declarations */
extern const struct rhashtable_params hq_params;
extern struct rhashtable hq_table;

extern struct dentry *debugfs;

int init_hq_context(struct hq_ctx *ctx, pid_t tgid);
int copy_hq_context(struct hq_ctx *new, struct hq_ctx *old, pid_t tgid);
void free_hq_context(void *pctx, void *arg);

#endif /* _HQ_MODULE_H_ */
