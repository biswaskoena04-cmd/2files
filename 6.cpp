// CVE-2023-49285 | CWE-126: Buffer Over-read
// parse_month() reads s[1] and s[2] without first checking that *s is
// non-NUL, enabling out-of-bounds reads on short or empty strings.
// Language: C

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const char *month_names[] = {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
};

// Helpers mirroring the original
static char xtoupper(char c) { return (char)toupper((unsigned char)c); }
static char xtolower(char c) { return (char)tolower((unsigned char)c); }

// VULNERABLE: does not check that s[0], s[1], s[2] are valid before reading.
// If `s` points to a string shorter than 3 characters, this reads past the end.
static int parse_month(const char *s) {
    int  i;
    char month[3];

    month[0] = xtoupper(*s);            // may read s[0]  = '\0' (benign but wrong)
    month[1] = xtolower(*(s + 1));      // may read s[1] past NUL  <-- BUG
    month[2] = xtolower(*(s + 2));      // may read s[2] past NUL  <-- BUG

    for (i = 0; i < 12; i++)
        if (!strncmp(month_names[i], month, 3))
            return i;
    return -1;
}

int main(void) {
    // Normal usage
    printf("Mar -> %d\n", parse_month("Mar"));
    printf("Dec -> %d\n", parse_month("December"));

    // Dangerous: empty string — reads past the NUL terminator
    printf("\"\" -> %d\n", parse_month(""));

    // Dangerous: one-character string
    printf("\"J\" -> %d\n", parse_month("J"));

    return 0;
}
