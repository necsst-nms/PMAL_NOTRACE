#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/nmm_top.h>
#include <linux/ktime.h>
ktime_t ktime_get(void);

asmlinkage size_t sys_nwrite(unsigned long fd, const char __user *buf, size_t count) {
	ktime_t start, end;
	s64 atime;
	start = ktime_get();

	size_t ret;
	// printk(KERN_ALERT "[sensong] sys_nwrite()\n");
	ret = nm_top_write(fd, buf, count);
	end = ktime_get();
	atime = ktime_to_ns(ktime_sub(end, start));
	printk(KERN_ALERT "[sensong] sys_nwrite() execution time = %lld\n", atime);
	return ret;
}
// asmlinkage long sys_nread(unsigned int fd, char __user *buf, size_t count);

