#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "monter-testlib.h"

#define DATA_SIZE 0x4000
#define INPUT_DATA_SIZE 0x1000

#define BITS 4096
#define SZ (BITS/8)

int main(int argc, char **argv) {
    int fd, i;
    char *data;
    FILE *input;
    uint32_t cmd[] = {
        MONTER_SWCMD_ADDR_AB(SZ * 2, SZ * 5),
        MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 8),
        MONTER_SWCMD_ADDR_AB(SZ * 6, SZ * 4),
        MONTER_SWCMD_RUN_REDC(SZ / 4, SZ * 8),
        MONTER_SWCMD_ADDR_AB(SZ * 3, SZ * 5),
        MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 10),
        MONTER_SWCMD_ADDR_AB(SZ * 6, SZ * 4),
        MONTER_SWCMD_RUN_REDC(SZ / 4, SZ * 10),
        MONTER_SWCMD_ADDR_AB(SZ * 9, SZ * 11),
        MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 0),
        MONTER_SWCMD_ADDR_AB(SZ * 6, SZ * 4),
        MONTER_SWCMD_RUN_REDC(SZ / 4, SZ * 0),
        MONTER_SWCMD_ADDR_AB(SZ * 1, SZ * 7),
        MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 8),
        MONTER_SWCMD_ADDR_AB(SZ * 6, SZ * 4),
        MONTER_SWCMD_RUN_REDC(SZ / 4, SZ * 8),
    };

    if (argc < 2) {
        fprintf(stderr, "Usage: %s input-file\n", argv[0]);
        return 1;
    }

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
    fclose(input);

    for (i = 0; i < sizeof(cmd)/sizeof(*cmd); i++)
        if (monter_write_single(fd, cmd[i]) != 4) {
            fprintf(stderr, "cmd %d failed: %s\n", i, strerror(errno));
            exit(1);
        }
    fsync(fd);
    monter_print_data(data+SZ*9, SZ);

    return 0;
}
