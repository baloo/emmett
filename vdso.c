#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <features.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void set_time(time_t *seconds)
{
	// printf("SET TIME\n");
	if (!seconds)
		return;
	*seconds = 42;
}

time_t time(time_t *x)
{
	time_t res;

	set_time(x);
	set_time(&res);
	return res;
}

time_t __vdso_time(time_t *x) { return time(x); }

int __gettimeofday(struct timeval *x, void *y)
{
	if (x == NULL)
		return -1;
	set_time(&x->tv_sec);
	return 0;
}

int gettimeofday(struct timeval *x, void *y) { return __gettimeofday(x, y); }
int __vdso_gettimeofday(struct timeval *x, void *y)
{
	return __gettimeofday(x, y);
}

int clock_gettime(clockid_t x, struct timespec *y)
{
	if (y == NULL)
		return -1;

	set_time(&y->tv_sec);
	return 0;
}

int __vdso_clock_gettime(clockid_t x, struct timespec *y)
{
	return clock_gettime(x, y);
}

int getcpu(unsigned int *cpu, unsigned int *node)
{
	printf("GET CPU\n");
	return 0;
}
int __vdso_getcpu(unsigned int *cpu, unsigned int *node)
{
	return getcpu(cpu, node);
}

int clock_getres(clockid_t clockid, struct timespec *res)
{
	printf("GET RES\n");
	return 0;
}
int __vdso_clock_getres(clockid_t clockid, struct timespec *res)
{
	return clock_getres(clockid, res);
}
