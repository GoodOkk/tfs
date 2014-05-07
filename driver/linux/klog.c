#include "klog.h"
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <stdarg.h>

#define KLOG_MSG_BYTES 200

static int klog_write_msg2(char **buff, int *left, const char *fmt, va_list args)
{
    	int res;

    	if (*left < 0)
        	return -1;

    	res = vsnprintf(*buff,*left,fmt,args);
    	if (res >= 0) {
        	*buff+=res;
        	*left-=res;
        	return 0;
    	} else {
        	return -2;
    	}
}

static int klog_write_msg(char **buff, int *left, const char *fmt, ...)
{
    	va_list args;
    	int res;

    	va_start(args,fmt);
    	res = klog_write_msg2(buff, left,fmt,args);
    	va_end(args);
    	return res;
}

static char * truncate_file_path(const char *filename)
{
    	char *temp, *curr = (char *)filename;
    	while((temp = strchr(curr,'/'))) {
    	    curr = ++temp;
    	}
    	return curr;
}


void klog(int level, const char *subcomp, const char *file, int line, const char *func, const char *fmt, ...)
{
    	char msg[KLOG_MSG_BYTES];
    	char *pos = msg;
    	int left = KLOG_MSG_BYTES - 1;
    	va_list args;
    	struct timespec ts;

    	getnstimeofday(&ts);

    	klog_write_msg(&pos,&left,"%s:[%lld.%.9ld][%d]%s():%s:%d, ", subcomp, (long long)ts.tv_sec, ts.tv_nsec, current->pid, func, truncate_file_path(file), line);

    	va_start(args,fmt);
    	klog_write_msg2(&pos,&left,fmt,args);
    	va_end(args);

    	msg[KLOG_MSG_BYTES-1] = '\0';

	switch (level) {
		case KL_INFO_L: 
    			printk(KERN_INFO "%s\n", msg);
			break;
		case KL_ERR_L:
    			printk(KERN_ERR "%s\n", msg);
			break;
		case KL_WARN_L:
    			printk(KERN_WARNING "%s\n", msg);
			break;
		case KL_DEBUG_L:
    			printk(KERN_DEBUG "%s\n", msg);
			break;
		default:	
	    		printk(KERN_INFO "%s\n", msg);
			break;
	}
}

