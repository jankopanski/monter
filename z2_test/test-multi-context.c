#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "monter-testlib.h"

#define DATA_SIZE 0x4000
#define INPUT_DATA_SIZE 0x800

#define BITS 2048
#define SZ (BITS/8)

void calculate(int fd, int sz) {
    int i, ret, done;
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
    for (i = 0; i < 32; i++) {
        done = 0;
        while (done < sizeof(cmd)) {
            ret = write(fd, cmd + done / 4, sizeof(cmd) - done);
            if (ret == -1) {
                fprintf(stderr, "iteration %d failed: %s\n", i, strerror(errno));
                exit(1);
            } else if (ret & 3) {
                fprintf(stderr, "iteration %d write returned %#x?!\n", i, ret);
                exit(1);
            }
            done += ret;
        }
    }
    fsync(fd);
}

int main(int argc, char **argv) {
    int fd;
    char *data;
    int i;
    int sz, data_size;
    pid_t pid;
    FILE *input;

    fd = monter_prepare(NULL, DATA_SIZE);
    if (fd < 0) {
        perror("monter_prepare");
        exit(1);
    }
    data = monter_mmap(fd, DATA_SIZE);
    if (data == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    input = fopen(argv[1], "r");
    if (!input) {
        perror("input file");
        return 1;
    }
    fread(data, INPUT_DATA_SIZE, 1, input);
    switch (pid = fork()) {
        case -1:
            perror("fork");
            exit(1);
        case 0:
            data_size = DATA_SIZE*2;
            sz = SZ*2;
            break;
        default:
            data_size = DATA_SIZE;
            sz = SZ;
            break;
    }
    if (!pid) {
        /* open new context and initialize it */
        fd = monter_prepare(NULL, data_size);
        if (fd < 0) {
            perror("monter_prepare");
            exit(1);
        }
        data = monter_mmap(fd, data_size);
        if (data == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }
        fread(data, INPUT_DATA_SIZE, 2, input);
    }
    fclose(input);

    calculate(fd, sz);
    if (pid) {
        int status;
        waitpid(pid, &status, 0);
        if (WEXITSTATUS(status))
            exit(WEXITSTATUS(status));
    }
    monter_print_data(data, sz);

    return 0;
}
