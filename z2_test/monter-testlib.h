#ifndef _MONTER_TESTLIB_H
#define _MONTER_TESTLIB_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "monter_ioctl.h"

extern int monter_prepare(char *path, int size);
extern int monter_write_single(int fd, uint32_t cmd);
extern char *monter_mmap(int fd, int size);
void monter_print_data(char *data, int size);

#define monter_write_single_checked(fd, cmd, msg) if (monter_write_single(fd, cmd) != 4) { \
    perror(msg); \
    exit(1); \
}

#define monter_write_single_invalid(fd, cmd, msg) if (monter_write_single(fd, cmd) != -1 || errno != EINVAL) { \
    fprintf(stderr, "%d: cmd %08x should fail with EINVAL bacause of: %s\n", __LINE__, cmd, msg); \
    exit(1); \
}

#endif
