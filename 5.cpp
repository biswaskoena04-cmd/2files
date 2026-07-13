// CVE-2020-29657 | CWE-125: Out-of-bounds Read
// jerry_port_read_source: checks only `!bytes_read` (zero) rather than
// `bytes_read != file_size`, so a short read silently returns a partial
// (potentially uninitialized) buffer — enabling out-of-bounds reads later.
// Language: C

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t uint8_t_alias;

// Dummy log
static void jerry_port_log(int level, const char *fmt, const char *arg) {
    (void)level;
    fprintf(stderr, fmt, arg);
}
#define JERRY_LOG_LEVEL_ERROR 0

// Simulated "get file size" helper
static size_t jerry_port_get_file_size(FILE *file_p) {
    long pos = ftell(file_p);
    fseek(file_p, 0, SEEK_END);
    long size = ftell(file_p);
    fseek(file_p, pos, SEEK_SET);
    return (size_t)size;
}

// VULNERABLE: checks `if (!bytes_read)` — only fails on zero bytes read.
// A short read (0 < bytes_read < file_size) will go undetected.
static uint8_t_alias *jerry_port_read_source(const char *file_name_p,
                                             size_t     *out_size_p) {
    FILE *file_p = fopen(file_name_p, "rb");
    if (file_p == NULL) {
        jerry_port_log(JERRY_LOG_LEVEL_ERROR,
                       "Error: failed to open file: %s\n", file_name_p);
        return NULL;
    }

    size_t file_size = jerry_port_get_file_size(file_p);
    uint8_t_alias *buffer_p = (uint8_t_alias *)malloc(file_size);
    if (buffer_p == NULL) {
        fclose(file_p);
        jerry_port_log(JERRY_LOG_LEVEL_ERROR,
                       "Error: failed to allocate memory for module", "");
        return NULL;
    }

    size_t bytes_read = fread(buffer_p, 1u, file_size, file_p);

    // VULNERABLE CHECK: only catches the zero-bytes case, not partial reads
    if (!bytes_read) {
        fclose(file_p);
        free(buffer_p);
        jerry_port_log(JERRY_LOG_LEVEL_ERROR,
                       "Error: failed to read file: %s\n", file_name_p);
        return NULL;
    }

    fclose(file_p);
    *out_size_p = bytes_read;
    return buffer_p;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    size_t size = 0;
    uint8_t_alias *buf = jerry_port_read_source(argv[1], &size);
    if (buf) {
        printf("Read %zu bytes\n", size);
        free(buf);
    }
    return 0;
}
