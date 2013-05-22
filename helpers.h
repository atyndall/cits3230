/// Provides helper functions

#ifndef HELPERS_H
#define HELPERS_H

#include <cnet.h>
#include <stdlib.h>
#include <string.h>

void info(CnetEvent ev, CnetTimerID timer, CnetData data);
void print_nic(CnetNICaddr addr);
void tprint_nic(char* desc, CnetNICaddr addr);

#endif // HELPERS_H