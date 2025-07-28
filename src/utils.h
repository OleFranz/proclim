#pragma once

#include <windivert.h>
#include <windows.h>

const char* pid_to_executable(const DWORD pid);
const char* ip_to_string(UINT32 address, bool is_ipv4);
const char* ipv4_to_string(UINT32 address);
const char* ipv6_to_string(UINT32 address);