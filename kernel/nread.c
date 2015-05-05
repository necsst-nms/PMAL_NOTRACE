#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/nmm_top.h>

asmlinkage unsigned long sys_nread(unsigned long fd, char __user *buf, size_t count) {
	unsigned long ret;
	printk(KERN_ALERT "[sensong] sys_nread()\n");
	ret = nm_top_read(fd, buf, count);
	printk(KERN_ALERT "[sensong] sys_nread() buf = %s\n", buf);
	return ret;
}
// asmlinkage long sys_nread(unsigned int fd, char __user *buf, size_t count);

