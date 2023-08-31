#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <atlsecurity.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <wininet.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Ws2_32")