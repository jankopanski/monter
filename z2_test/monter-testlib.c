#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "monter_ioctl.h"

int monter_prepare(char *path, int size) {
    int fd;
    int ret;

    if (!path)
        path = "/dev/monter0";

    fd = open(path, O_RDWR);

    if (fd == -1)
        return fd;
    ret = ioctl(fd, MONTER_IOCTL_SET_SIZE, size);
    if (ret == -1)
        return ret;
    return fd;
}

int monter_write_single(int fd, uint32_t cmd) {
    return write(fd, &cmd, 4);
}

char *monter_mmap(int fd, int size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
}

void monter_print_data(char *data, int size) {
    int i;
    for (i = 0; i < size; i++) {
        printf("%02hhX", data[i]);
    }
    printf("\n");
}
