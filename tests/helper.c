#include "helper.h"

int capture_stdout(char *buffer, size_t size, void (*func)(void))
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
        return -1;

    fflush(stdout);

    int old_stdout = dup(STDOUT_FILENO);

    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    func();

    fflush(stdout);

    dup2(old_stdout, STDOUT_FILENO);
    close(old_stdout);

    int n = read(pipefd[0], buffer, size - 1);
    if (n < 0)
        n = 0;

    buffer[n] = '\0';
    close(pipefd[0]);

    return n;
}

void run_test(int (*test_func)(void), const char *name, int *tests_passed, int *tests_failed, int *total) {
    printf("[%d]: %s\n",++(*total), name);
    int rc = test_func();
    if (rc == 0) {
        (*tests_passed)++;
    } else {
        (*tests_failed)++;
        fprintf(stderr, "Test failed: %s\n", name);
    }
}