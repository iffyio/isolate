#ifndef ISOLATE_UTIL_H
#define ISOLATE_UTIL_H

static void die(const char *fmt, ...)
{
    va_list params;

    va_start(params, fmt);
    vfprintf(stderr, fmt, params);
    va_end(params);
    exit(1);
}

#endif //ISOLATE_UTIL_H
