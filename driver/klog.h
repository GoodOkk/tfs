#pragma once

#define KL_INFO_L 	1
#define KL_ERR_L 	2
#define KL_DEBUG_L	3
#define KL_WARN_L 	4

#define KL_INFO 	KL_INFO_L,__SUBCOMPONENT__,__FILE__, __LINE__, __FUNCTION__
#define KL_ERR 		KL_ERR_L,__SUBCOMPONENT__,__FILE__, __LINE__, __FUNCTION__
#define KL_DEBUG	KL_DEBUG_L,__SUBCOMPONENT__,__FILE__, __LINE__, __FUNCTION__
#define KL_WARN 	KL_WARN_L,__SUBCOMPONENT__,__FILE__, __LINE__, __FUNCTION__


void klog(int level, const char *subcomp, const char *file, int line, const char *func, const char *fmt, ...);

int klog_init(void);

void klog_release(void);

#define ENTER_FUNC \
  klog(KL_INFO, "Enter %s", __FUNCTION__);

#define LEAVE_FUNC \
  klog(KL_INFO, "Leave %s", __FUNCTION__);

