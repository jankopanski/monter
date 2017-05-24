#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "monter-testlib.h"

int main(int argc, char **argv) {
    int fd, i;
    int ret;
    uint32_t cmd;
    char *data;
    uint32_t cmds[4];

    fd = open("/dev/monter0", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    if (ioctl(fd, MONTER_IOCTL_SET_SIZE, 0x10004) != -1 || errno != EINVAL) {
        fprintf(stderr, "MONTER_IOCTL_SET_SIZE should fail - too large buffer\n");
        exit(1);
    }
    if (ioctl(fd, MONTER_IOCTL_SET_SIZE, 0x3) != -1 || errno != EINVAL) {
        fprintf(stderr, "MONTER_IOCTL_SET_SIZE should fail - not aligned to page size\n");
        exit(1);
    }
    if (ioctl(fd, 1, 0) != -1 || errno != ENOTTY) {
        fprintf(stderr, "invalid ioctl should be rejected with ENOTTY\n");
        exit(1);
    }
    monter_write_single_invalid(fd, MONTER_SWCMD_ADDR_AB(0, 0), "before set_size");
    if (ioctl(fd, MONTER_IOCTL_SET_SIZE, 0x1000) != 0) {
        perror("set_size");
        exit(1);
    }
    if (ioctl(fd, MONTER_IOCTL_SET_SIZE, 0x2000) != -1 || errno != EINVAL) {
        fprintf(stderr, "second MONTER_IOCTL_SET_SIZE should fail\n");
        exit(1);
    }
    data = monter_mmap(fd, 0x1000);
    if (data == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memset(data, 0, 0x1000);
    cmd = MONTER_SWCMD_ADDR_AB(0x100, 0x120);
    if (write(fd, &cmd, 3) != -1) {
        fprintf(stderr, "not aligned write should fail\n");
        exit(1);
    }
    for (cmd = 0; cmd < 0x10; cmd++) {
        if (cmd == MONTER_SWCMD_TYPE_ADDR_AB)
            continue;
        if (cmd == MONTER_SWCMD_TYPE_RUN_MULT)
            continue;
        if (cmd == MONTER_SWCMD_TYPE_RUN_REDC)
            continue;
        monter_write_single_invalid(fd, cmd, "invalid cmd");
    }
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_MULT(64, 128), "RUN_MULT before ADDR_AB");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_REDC(64, 128), "RUN_REDC before ADDR_AB");
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0, 64), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_MULT(64, 128) | 1<<17, "unexpected bits set");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_REDC(64, 128) | 1<<17, "unexpected bits set");
    monter_write_single_invalid(fd, MONTER_SWCMD_ADDR_AB(0x4000, 64), "outside of data area");
    monter_write_single_invalid(fd, MONTER_SWCMD_ADDR_AB(64, 0x4000), "outside of data area");
    /* check if the second set_size really was ignored */
    monter_write_single_invalid(fd, MONTER_SWCMD_ADDR_AB(0x1200, 0x1200), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_MULT(64, 0x1000), "result outside of data area");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_REDC(64, 0x1000), "result outside of data area");
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0, 0xffc), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_MULT(64, 0x800), "B outside of data area");
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0xffc, 0), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_invalid(fd, MONTER_SWCMD_RUN_MULT(64, 0x800), "A outside of data area");
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(0xffc, 0), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_checked(fd, MONTER_SWCMD_RUN_REDC(64, 0x800), "A is smaller for REDC, should be accepted");

    fsync(fd);
    monter_print_data(data, 0x1000);

    memset(data, 0xcc, 64);
    memset(data+64, 0, 64);
    data[64] = 1;
    memset(data+128, 0, 256);
    cmds[0] = MONTER_SWCMD_ADDR_AB(0, 64);
    cmds[1] = MONTER_SWCMD_RUN_MULT(64, 128);
    cmds[2] = 0x7; /* invalid cmd */
    switch (ret = write(fd, cmds, 12)) {
        case -1:
            if (errno != EINVAL) {
                fprintf(stderr, "Command should be rejected with EINVAL(%d), not %d\n", EINVAL, errno);
                exit(1);
            }
            /* if rejected - check if reall whole buffer was rejected */
            fsync(fd);
            if (memcmp(data+128, data+256, 128) != 0) {
                fprintf(stderr, "write returned -EINVAL, but some commands were processed\n");
                exit(1);
            }
            break;
        case 8:
            fsync(fd);
            if (memcmp(data+128, data, 64) != 0) {
                fprintf(stderr, "write returned 8, but first two commands weren't processed\n");
                exit(1);
            }
            break;
        default:
            fprintf(stderr, "%d\n", ret);
            fprintf(stderr, "either the whole buffer should be rejected, or just the invalid command\n");
            exit(1);
    }

    return 0;
}
