#ifndef _HQ_COMPAT_H_
#define _HQ_COMPAT_H_

// not defined until glibc >= 2.28
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE (MAP_SHARED | MAP_PRIVATE)
#endif /* MAP_SHARED_VALIDATE */

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif /* MAP_FIXED_NOREPLACE */

// from kernel include/linux/err.h
#define MAX_ERRNO 4095

// from kernel ipc/mqueue.c
#define MQUEUE_MAGIC 0x19800202

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif /* MAP_HUGE_SHIFT */

#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif /* MAP_HUGE_1GB */

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif /* MAP_HUGE_2MB */

#endif /* _HQ_COMPAT_H_ */
