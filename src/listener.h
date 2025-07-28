#pragma once

#include <windivert.h>

// windivert.h (v2.2.2-A) does not include this for some reason...
#define IPPROTO_ICMPV6 58

#include <unordered_map>
#include <windows.h>
#include <cstdint>
#include <psapi.h>
#include <chrono>
#include <cstdio>
#include <vector>
#include <mutex>

#include "error.h"
#include "utils.h"


void flow_layer_listener();
void network_layer_listener();