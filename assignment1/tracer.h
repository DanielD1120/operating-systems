/*
 * SO2 kprobe based tracer header file
 *
 * this is shared with user space
 */

#ifndef TRACER_H__
#define TRACER_H__ 1

#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#define TRACER_DEV_MINOR    42
#define TRACER_DEV_NAME     "tracer"
#define TRACER_FILE_READ    "tracer"

#define KMALLOC_FUNCTION    "__kmalloc"
#define KFREE_FUNCTION      "kfree"
#define SCHEDULE_FUNCTION   "schedule"
#define UP_FUNCTION         "up"
#define DOWN_FUNCTION       "down_interruptible"
#define LOCK_FUNCTION       "mutex_lock_nested"
#define UNLOCK_FUNCTION     "mutex_unlock"

#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)

#endif /* TRACER_H_ */
