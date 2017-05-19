#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "monter-testlib.h"

#define BASE_BITS 1024
#define BASE_INPUT_SIZE 0x400
#define BASE_SZ (BASE_BITS/8)

void calculate(int fd, int sz, int count) {
    int i;
    uint32_t cmd[] = {
        MONTER_SWCMD_ADDR_AB(sz * 0, sz * 5),
        MONTER_SWCMD_RUN_MULT(sz / 4, sz * 8),
        MONTER_SWCMD_ADDR_AB(sz * 6, sz * 4),
        MONTER_SWCMD_RUN_REDC(sz / 4, sz * 8),
        MONTER_SWCMD_ADDR_AB(sz * 3, sz * 5),
        MONTER_SWCMD_RUN_MULT(sz / 4, sz * 10),
        MONTER_SWCMD_ADDR_AB(sz * 6, sz * 4),
        MONTER_SWCMD_RUN_REDC(sz / 4, sz * 10),
        MONTER_SWCMD_ADDR_AB(sz * 9, sz * 11),
        MONTER_SWCMD_RUN_MULT(sz / 4, sz * 0),
        MONTER_SWCMD_ADDR_AB(sz * 6, sz * 4),
        MONTER_SWCMD_RUN_REDC(sz / 4, sz * 0),
        MONTER_SWCMD_ADDR_AB(sz * 1, sz * 7),
        MONTER_SWCMD_RUN_MULT(sz / 4, sz * 8),
        MONTER_SWCMD_ADDR_AB(sz * 6, sz * 4),
        MONTER_SWCMD_RUN_REDC(sz / 4, sz * 8),
        MONTER_SWCMD_ADDR_AB(sz * 9, sz * 7),
        MONTER_SWCMD_RUN_MULT(sz / 4, sz * 0),
    };
    while (count--)
        for (i = 0; i < sizeof(cmd)/sizeof(*cmd); i++)
            if (monter_write_single(fd, cmd[i]) != 4) {
                fprintf(stderr, "cmd %d failed: %s\n", i, strerror(errno));
                exit(1);
            }
    fsync(fd);
}

int main(int argc, char **argv) {
    int fd;
    char *data;
    int i;
    pid_t pid;
    int size, sz, count;
    FILE *input;

    size = 0x4000;
    sz = BASE_SZ;
    count = 16;

    input = fopen(argv[1], "r");
    if (!input) {
        perror("input file");
        return 1;
    }
    fd = monter_prepare("/dev/monter0", size);
    if (fd < 0) {
        perror("monter_prepare");
        exit(1);
    }
    data = monter_mmap(fd, size);
    if (data == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    fread(data, BASE_INPUT_SIZE, 1, input);

    switch (pid = fork()) {
        case -1:
            perror("fork");
            exit(1);
        case 0:
            size = 0x4000;
            sz = BASE_SZ*2;
            count = 8;

            fd = monter_prepare("/dev/monter1", size);
            if (fd < 0) {
                perror("monter_prepare");
                exit(1);
            }
            data = monter_mmap(fd, size);
            if (data == MAP_FAILED) {
                perror("mmap");
                exit(1);
            }
            fread(data, BASE_INPUT_SIZE, 2, input);
            break;
        default:
            break;
    }
    fclose(input);

    calculate(fd, sz, count);

    if (pid) {
        int status;
        waitpid(pid, &status, 0);
        if (WEXITSTATUS(status))
            exit(WEXITSTATUS(status));
    }
    monter_print_data(data, sz);

    return 0;
}
