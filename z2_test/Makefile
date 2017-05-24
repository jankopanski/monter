# TESTS = \
# 		test-simple \
# 		test-invalid \
# 		test-mmap-later \
# 		test-reuse-addr \
# 		test-long-queue \
# 		test-multi-context \
# 		test-big-writes \
# 		test-multi-device

TESTS = test-reuse-addr

CFLAGS = -g
LDFLAGS =

test: $(TESTS:%=%.test)
all: $(TESTS) $(TESTS:%=%-input)

SHELL = /bin/bash
.PHONY: %.test

%-input %-output: %-gen.py
	./$< $*-input $*-output

%.test: % %-input %-output /dev/monter0
	-diff -q $<-output <(./$< $<-input)

test-multi-device.test: /dev/monter1

.SECONDARY: $(TESTS)
test%: test%.o monter-testlib.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TESTS) *.o

clean-all: clean
	rm -f *-input *-output
