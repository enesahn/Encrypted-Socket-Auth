#pragma once
#include "keyauth.hpp"
#include <random>

std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
    using namespace CryptoPP;

    std::string ciphertext;
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()));

    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    return ciphertext;
}

std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    using namespace CryptoPP;

    std::string decryptedtext;
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(reinterpret_cast<const byte*>(key.data()), key.size(), reinterpret_cast<const byte*>(iv.data()));

    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decryptedtext)
        )
    );

    return decryptedtext;
}

class ClientHandler {
private:
    SOCKET clientfd{};
    struct sockaddr cli_addr = {};
    int addr_len{};
    struct packet_data packet = {};

public:
    std::string client_ip{};

    ClientHandler(const SOCKET& _clientfd, const std::string& _client_ip, const struct sockaddr& _cli_addr, const int& _addr_len) {
        clientfd = _clientfd;
        client_ip = _client_ip;
        cli_addr = _cli_addr;
        addr_len = _addr_len;
    }

    bool handle_packet() {
        uint64_t timestamp = get_timestamp();
        packet.timestamp = timestamp;
        // paketi burada þifrele
        if (sendto(clientfd, reinterpret_cast<const char*>(&packet), sizeof(packet_data), 0, &cli_addr, addr_len) == SOCKET_ERROR) {
            logger->warning("%s package could not be sent to your address:", client_ip.c_str());
            return false;
        }
        do {
            if (recvfrom(clientfd, reinterpret_cast<char*>(&packet), sizeof(packet_data), 0, &cli_addr, &addr_len) == SOCKET_ERROR) {
                logger->warning("%s failed to receive package from:", client_ip.c_str());
                return false;
            }

            // paketi burada çöz
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (packet.timestamp == timestamp || packet.timestamp == 0); // ignore own and NULL packets
        if (packet.action != packet_action::CLIENT_SUCCESS) {
            // either an error occurred during data transfer or the packet was modified
            logger->warning("%s failed to receive expected package at:", client_ip.c_str());
            sender("3138752", "Failed to receive expected package at", + "**IP: ** " + client_ip);
            return false;
        }
        return true;
    }

    bool login() {
        packet = create_packet(packet_action::SEND_KEY_HWID);
        if (!handle_packet()) {
            logger->warning("%s failed to receive key packet from:", client_ip.c_str());
            return false;
        }

        struct key_hwid_packet_buffer buf = *(struct key_hwid_packet_buffer*)(packet.buffer);

        std::string decryptedKey = decrypt(buf.key, "0123456789abcdef", buf.iv);
        std::string decryptedHwid = decrypt(buf.hwid, "0123456789abcdef", buf.iv);
        std::string decryptedVer = decrypt(buf.version, "0123456789abcdef", buf.iv);

        keyauth_result result = keyauth::check_user(decryptedKey, decryptedHwid, decryptedVer);
        switch (result) {
        case keyauth_result::VALID: {
            client_ip += " (" + std::string(decryptedKey) + ")";
            logger->info("%s New client connected", client_ip.c_str());
            return true;
        }

        default: {
            packet = create_packet(packet_action::KEY_CHECK_FAILED);
            struct invalid_key_packet_buffer out_buf = {};
            out_buf.result = result;
            *(struct invalid_key_packet_buffer*)(packet.buffer) = out_buf;
            uint64_t timestamp = get_timestamp();
            packet.timestamp = timestamp;
            // paketi burada þifrele
            if (sendto(clientfd, reinterpret_cast<const char*>(&packet), sizeof(packet_data), 0, &cli_addr, addr_len) == SOCKET_ERROR) {
                logger->warning("%s Failed to send an incorrect key packet to the address:", client_ip.c_str());
                return false;
            }
            return false;
        }
        }
        return false; // buraya nasýl geldik?
    }

    bool start_application() {
        packet = create_packet(packet_action::OPEN_MESSAGEBOX);
        open_messagebox_packet_buffer buf{};
        buf.hWnd = 0;
        strcpy_s(buf.text, "Merhaba, Dunya!");
        strcpy_s(buf.caption, "MessageBox");
        buf.type = 0; // MB_OK = 0
        *(open_messagebox_packet_buffer*)(packet.buffer) = buf;
        if (!handle_packet()) {
            logger->warning("%s failed to receive messagebox package from", client_ip.c_str());
            return false;
        }
        return true;
    }
};
