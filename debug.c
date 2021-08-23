#include <stdio.h>
#include <sys/auxv.h>
#include <sys/time.h>

int main(void)
{
	void *vdso = (void *)getauxval(AT_SYSINFO_EHDR);
	printf("[vdso: %p]\n", vdso);

	struct timeval tv;
	memset(&tv, 0, sizeof(struct timeval));

	int rv = gettimeofday(&tv, NULL);
	printf("[tv.sec: %d (rv=%d)]\n", tv.tv_sec, rv);

	return 1;
}
