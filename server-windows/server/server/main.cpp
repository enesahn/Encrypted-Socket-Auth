#include <iostream>
#include <thread>
#include <WinSock2.h>
#include "client_handler.hpp"

constexpr const unsigned int port = 1337; // You can change the port as desired
// Make sure it matches the port that only clients connect to

const std::string get_ip(const uint32_t& addr) {
    std::string out = "";
    for (uint64_t i = 0; i < sizeof(addr); i++) {
        out += std::to_string((uint32_t)(*(uint8_t*)((uint64_t)&addr + i)));
        if (i != sizeof(addr) - 1) {
            out += ".";
        }
    }
    return out;
}

void handle_client(const SOCKET clientfd, sockaddr cli_addr, int addr_len) {
    std::string client_ip = get_ip(reinterpret_cast<struct sockaddr_in*>(&cli_addr)->sin_addr.s_addr);
    logger->info("new client connected: %s", client_ip.c_str());
    clientip = client_ip.c_str();

    ClientHandler client_handler = ClientHandler(clientfd, client_ip, cli_addr, addr_len);

    try {
        if (!client_handler.login()) {
            closesocket(clientfd);
            return;
        }
    }
    catch (std::exception& e) {
        logger->error("failed to check user %s because %s", client_handler.client_ip.c_str(), e.what());
        closesocket(clientfd);
        return;
    }

    try {
        if (!client_handler.start_application()) {
            closesocket(clientfd);
            return;
        }
    }
    catch (std::exception& e) {
        logger->error("failed to start application main on %s because %s", client_handler.client_ip.c_str(), e.what());
        closesocket(clientfd);
        return;
    }

    closesocket(clientfd);
}


int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize WinSock." << std::endl;
        return -1;
    }

    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "Failed to create socket." << std::endl;
        WSACleanup();
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(sockfd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Failed to connect to port." << std::endl;
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    if (listen(sockfd, 100) == SOCKET_ERROR) { // Ayný anda 100 istemciye izin ver
        std::cerr << "Failed to initialize listener." << std::endl;
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    std::cout << "Port " << port << " listening..." << std::endl;

    while (true) {
        sockaddr_in cli_addr;
        int clilen = sizeof(cli_addr);
        SOCKET clientfd = accept(sockfd, reinterpret_cast<sockaddr*>(&cli_addr), &clilen);
        if (clientfd == INVALID_SOCKET) {
            std::cerr << "Failed to accept new client." << std::endl;
            continue;
        }

        std::thread([&](SOCKET clientfd, sockaddr_in cli_addr, int addr_len) {
            handle_client(clientfd, *reinterpret_cast<sockaddr*>(&cli_addr), addr_len);
            }, clientfd, cli_addr, clilen).detach();
    }

    closesocket(sockfd);
    WSACleanup();
    return 0;
}
