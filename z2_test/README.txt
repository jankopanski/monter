Sposób użycia: make
Można też osobno skompilować testy: make all
Jak również uruchomić: make test


Przykład poprawnego wykonania testów:
    # make test
    diff -q test-simple-output <(./test-simple test-simple-input)
    diff -q test-invalid-output <(./test-invalid test-invalid-input)
    diff -q test-mmap-later-output <(./test-mmap-later test-mmap-later-input)
    diff -q test-reuse-addr-output <(./test-reuse-addr test-reuse-addr-input)
    diff -q test-long-queue-output <(./test-long-queue test-long-queue-input)
    diff -q test-multi-context-output <(./test-multi-context test-multi-context-input)
    diff -q test-big-writes-output <(./test-big-writes test-big-writes-input)
    diff -q test-multi-device-output <(./test-multi-device test-multi-device-input)

Test "test-multi-device" wymaga aby w systemie były co najmniej dwa urządzenia monter.

Za każdy z testów można dostać 0.625 punktów.
