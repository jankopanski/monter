#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "monter-testlib.h"

#define BASE_BITS 1024
#define BASE_INPUT_SIZE 0x400
#define BASE_SZ (BASE_BITS/8)

void calculate(int fd, int sz, int count) {
    int i, ret, done, total_size;
    uint32_t *cmds;
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
    total_size = count * sizeof(cmd);
    cmds = malloc(total_size);
    if (!cmds) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    for (i = 0; i < count; i++)
        memcpy(cmds + (sizeof(cmd) / sizeof(*cmd)) * i, cmd, sizeof(cmd));

    done = 0;
    while (done < total_size) {
        ret = write(fd, cmds + done / 4, total_size - done);
        if (ret == -1) {
            fprintf(stderr, "iteration %d failed: %s\n", i, strerror(errno));
            exit(1);
        } else if (ret & 3) {
            fprintf(stderr, "iteration %d write returned %#x?!\n", i, ret);
            exit(1);
        }
        done += ret;
    }
    fsync(fd);
}


int main(int argc, char **argv) {
    int fd;
    char *data;
    int i, rc;
    uint32_t *cmds;
    pid_t pid;
    int size, sz, count;
    FILE *input;

    input = fopen(argv[1], "r");
    if (!input) {
        perror("input file");
        return 1;
    }

    // first process:
    size = 0x1000;
    sz = BASE_SZ*2;
    count = 32;

    fd = monter_prepare(NULL, size);
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
    //fclose(input);

    switch (pid = fork()) {
        case -1:
            perror("fork");
            exit(1);
        case 0:
            // second process:
            size = 0x2000;
            sz = BASE_SZ*4;
            count = 16;

            fd = monter_prepare(NULL, size);
            if (fd < 0) {
                perror("monter_prepare");
                exit(1);
            }
            data = monter_mmap(fd, size);
            if (data == MAP_FAILED) {
                perror("mmap");
                exit(1);
            }
            fread(data, BASE_INPUT_SIZE, 4, input);
            
            switch (pid = fork()) {
                case -1:
                    perror("fork");
                    exit(1);
                case 0:
                    // third process:
                    size = 0x4000;
                    sz = BASE_SZ*8;
                    count = 8;

                    fd = monter_prepare(NULL, size);
                    if (fd < 0) {
                        perror("monter_prepare");
                        exit(1);
                    }
                    data = monter_mmap(fd, size);
                    if (data == MAP_FAILED) {
                        perror("mmap");
                        exit(1);
                    }
                    fread(data, BASE_INPUT_SIZE, 8, input);

                    switch (pid = fork()) {
                        case -1:
                            perror("fork");
                            exit(1);
                        case 0:
                            // fourth process:
                            size = 0x1000;
                            sz = BASE_SZ;
                            count = 64;

                            fd = monter_prepare(NULL, size);
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
                    }
            }
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
