#ifndef PRAGMA_H
#define PRAGMA_H

typedef int (*detector_pragma_cb)(const char *category, const char *model,
                                  float threshold, void *ctx);

int scan_debug_pragma(char *src);
int scan_aggressive_pragma(char *src);
int scan_detector_pragmas(const char *src, detector_pragma_cb cb, void *ctx);
int scan_pattern_pragmas(const char *src, detector_pragma_cb cb, void *ctx);

#endif
