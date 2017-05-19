#include <sys/mman.h>
#include <string.h>
#include "monter-testlib.h"

/* make sure no kernel data is leaked through uninitialized buffer */

int main(int argc, char **argv) {
    int fd, i;
    char *data;

    fd = monter_prepare(NULL, 0x1000);
    if (fd < 0) {
        perror("monter_prepare");
        exit(1);
    }
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0, 0x400), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_checked(fd, MONTER_SWCMD_RUN_MULT(0x100, 0x800), "MONTER_SWCMD_RUN_MULT");
    fsync(fd);
    data = monter_mmap(fd, 0x1000);
    if (data == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    monter_print_data(data, 0x1000);
    fflush(stdout);

    /* if this isn't enough, try to exit the process without waiting for
     * operations to complete */

    fd = monter_prepare(NULL, 0x1000);
    if (fd < 0) {
        perror("monter_prepare");
        exit(1);
    }
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0, 0x400), "MONTER_SWCMD_ADDR_AB");
    i = 0x10;
    while (i--)
        monter_write_single_checked(fd, MONTER_SWCMD_RUN_MULT(0x100, 0x800), "MONTER_SWCMD_RUN_MULT");

    kill(getpid(), 9);

    return 0;
}
