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
    fread(data, SZ, 2, input);
    // fprintf(stderr, "A\n");
    // monter_print_data(data, SZ);
    // fprintf(stderr, "B\n");
    // monter_print_data(data + SZ, SZ);
    // monter_print_data(data, 2 * SZ);
    monter_write_single_checked(fd, MONTER_SWCMD_ADDR_AB(SZ * 0, SZ * 1), "MONTER_SWCMD_ADDR_AB");
    monter_write_single_checked(fd, MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 2), "MONTER_SWCMD_RUN_MULT 1");
    fsync(fd);
    fread(data, SZ, 2, input);
    // fread(data + 2 * SZ, SZ, 2, input);
    // monter_print_data(data  , 2 * SZ);
    monter_write_single_checked(fd, MONTER_SWCMD_RUN_MULT(SZ / 4, SZ * 4), "MONTER_SWCMD_RUN_MULT 2");
    fclose(input);

    fsync(fd);
    monter_print_data(data + SZ * 2, SZ * 2);
    monter_print_data(data + SZ * 4, SZ * 2);

    return 0;
}
