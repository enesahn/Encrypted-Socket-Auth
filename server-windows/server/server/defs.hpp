#pragma once
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <ctime>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sys/types.h>
#include <curl/curl.h>
#include "json.hpp"
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Ws2_32")