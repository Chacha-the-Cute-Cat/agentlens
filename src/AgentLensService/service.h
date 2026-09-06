#pragma once

#include <cstdio>

int RunService();
int RunConsole();
void SetEventOptions(FILE* output, unsigned long long filterPid, unsigned long filterType);
