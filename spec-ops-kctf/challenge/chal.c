#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Spec Ops -- Field Terminal
 *
 * field_report() feeds whatever the operator sends straight into printf()
 * as the FORMAT argument instead of as data ("printf(buf)" instead of
 * "printf(\"%s\", buf)"). That's the whole bug. Input is read with a raw
 * read() (not fgets/scanf) so a real GOT-overwrite payload -- which is
 * arbitrary binary data and will usually contain 0x0a/0x00 bytes as part
 * of the target addresses -- reaches the format string intact.
 *
 * The terminal takes two field reports before debriefing -- a real
 * operator files a status update, then a follow-up. That's exactly
 * enough room to leak an address on report #1 and use it on report #2.
 */

static long read_line(char *buf, size_t cap) {
    long n = read(STDIN_FILENO, buf, cap - 1);
    if (n <= 0) exit(0);
    buf[n] = 0;
    /* only strip a *trailing* newline -- payload bytes in the middle stay untouched */
    if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = 0;
    return n;
}

void field_report(int round) {
    char buf[264];

    printf("Enter field report #%d: ", round);
    fflush(stdout);
    read_line(buf, sizeof(buf));

    printf(buf);   /* <-- the vulnerability */
    printf("\n");
    fflush(stdout);
}

void debrief(void) {
    char note[264];

    printf("Enter closing message: ");
    fflush(stdout);
    read_line(note, sizeof(note));

    puts("Transmission ends.");
    puts(note);   /* <-- once puts()'s GOT entry has been hijacked to
                    *     system(), this call becomes system(note) */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("=====================================");
    puts("   SPEC OPS -- Field Terminal v1.4");
    puts("=====================================");

    field_report(1);
    field_report(2);
    debrief();

    puts("Session closed.");
    return 0;
}
