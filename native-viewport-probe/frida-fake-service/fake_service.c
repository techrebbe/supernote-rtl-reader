#include <windows.h>
#include <stdio.h>
#include <string.h>

static volatile LONG score = 0;

__declspec(dllexport) __declspec(noinline)
void __cdecl fake_setter(int value) {
    InterlockedExchange(&score, (LONG)value);
}

__declspec(dllexport) __declspec(noinline)
int __cdecl fake_score(void) {
    return (int)InterlockedCompareExchange(&score, 0, 0);
}

int main(void) {
    char command[80];
    int value;
    char extra;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("READY %lu\n", (unsigned long)GetCurrentProcessId());

    while (fgets(command, sizeof(command), stdin) != NULL) {
        if (sscanf(command, "SET %d %c", &value, &extra) == 1) {
            fake_setter(value);
            printf("SCORE %d\n", fake_score());
        } else if (strcmp(command, "SENTINEL\n") == 0) {
            /* Exercise the original export repeatedly after the hook is gone. */
            for (value = 1; value <= 8; ++value) {
                fake_setter(0x13570000 + value);
                if (fake_score() != 0x13570000 + value) {
                    printf("SENTINEL_FAIL %d\n", value);
                    return 2;
                }
            }
            printf("SENTINEL_OK 8\n");
        } else if (strcmp(command, "QUIT\n") == 0) {
            puts("BYE");
            return 0;
        } else {
            puts("ERR");
        }
    }

    return 0;
}
