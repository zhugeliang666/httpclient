#pragma once



// 若有头文件间接包含 winsock.h，阻止它（确保只用 winsock2）
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
// ---------- C++ Standard Library ----------
#include <algorithm>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include <codecvt>
#include <cstdio>

// ---------- Sockets / Networking (顺序很重要) ----------
#include <winsock2.h>        // 必须在 windows.h 之前
#include <ws2tcpip.h>

// ---------- Windows Base ----------
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <versionhelpers.h>
#include <tlhelp32.h>

// ---------- Graphics ----------
#include <gdiplus.h>         // 依赖 windows.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#undef max
// ---------- Third-party ----------
#include "json.hpp"          // 建议：若使用 nlohmann/json，改为 <nlohmann/json.hpp>
#include "zlib.h"
#include <curl/curl.h>


// ---------- System / IP Helper / WMI ----------
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>

// ---------- Intrinsics / SIMD ----------
#include <intrin.h>
#include <nmmintrin.h>       // SSE4.2（含 POPCNT 等）


// ---------- Pragmas: link libraries ----------
#pragma comment(lib, "Ws2_32.lib")     // winsock
#pragma comment(lib, "Iphlpapi.lib")   // ip helper
#pragma comment(lib, "wbemuuid.lib")   // WMI
#pragma comment(lib, "Gdiplus.lib")    // GDI+
#pragma comment(lib, "Crypt32.lib")    // 若用到 WinCrypt
#pragma comment(lib, "Winmm.lib")      // 如需 timeGetTime 等，再按需加





void report();
