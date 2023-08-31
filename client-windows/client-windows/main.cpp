#include "packet.hpp"
#include "logger.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <random>

using namespace std;

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
	decryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()));

	StringSource(ciphertext, true,
		new StreamTransformationFilter(decryptor,
			new StringSink(decryptedtext)
		)
	);

	return decryptedtext;
}

std::string serialize_packet(const packet_data& packet) {
	return std::string(reinterpret_cast<const char*>(&packet), sizeof(packet_data));
}

void deserialize_packet(const std::string& data, packet_data& packet) {
	memcpy(&packet, data.data(), sizeof(packet_data));
}

constexpr const u_short port = 1337; // replace with your port
SOCKADDR sock_addr{};
int sock_len = sizeof(SOCKADDR);
uint64_t last_timestamp = 1337;
packet_data packet{};

static std::string get_hwid() {
	ATL::CAccessToken accessToken;
	ATL::CSid currentUserSid;
	if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
		accessToken.GetUser(&currentUserSid))
		return std::string(CT2A(currentUserSid.Sid()));
}

SOCKET connect_to_server() {
	SOCKADDR_IN address{};
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	sock_addr = *(SOCKADDR*)&sock_addr;
	inet_pton(AF_INET, "3.214.252.223", &address.sin_addr.s_addr); // replace with your server ip

	const SOCKET connection = socket(AF_INET, SOCK_STREAM, 0);
	if (connection == INVALID_SOCKET) {
		return INVALID_SOCKET;
	}

	if (connect(connection, (SOCKADDR*)&address, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		closesocket(connection);
		return INVALID_SOCKET;
	}

	return connection;
}

__forceinline std::string get_random_string(size_t length)
{
	std::string str(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"));
	std::random_device rd;
	std::mt19937 generator(rd());
	std::shuffle(str.begin(), str.end(), generator);
	return str.substr(0, length);
}

int main() {
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data)) { // we wanna use WinSock 2.2
		logger->error("failed to init WinSock 2.2");
		return -1;
	}

	const SOCKET sock = connect_to_server();
	if (sock == INVALID_SOCKET) {
		logger->error("failed to connect to server");
		return -1;
	}

	while (true) {
		memset(&packet, 0, sizeof(packet_data));
		if (recvfrom(sock, (char*)&packet, sizeof(packet_data), 0, &sock_addr, &sock_len) < 0) {
			logger->error("failed to receive packet from server");
			return -1;
		}

		// decrypt packet here

		if (packet.timestamp == last_timestamp || packet.timestamp == 0) {
			continue; // ignore own or NULL packet
		}

		switch (packet.action) {
		case packet_action::SEND_KEY_HWID: {
			key_hwid_packet_buffer buf{};
			strcpy_s(buf.iv, get_random_string(16).c_str());
			std::string version = "1.6";
			std::string hwid = get_hwid();
			std::string key{};
			logger->info("please enter your key");
			std::cin >> key;

			packet = create_packet(packet_action::CLIENT_SUCCESS);
			last_timestamp = get_timestamp();
			packet.timestamp = last_timestamp;

			key = encrypt(key, "0123456789abcdef", buf.iv);
			hwid = encrypt(hwid, "0123456789abcdef", buf.iv);
			version = encrypt(version, "0123456789abcdef", buf.iv);

			strcpy_s(buf.key, key.c_str());
			strcpy_s(buf.hwid, hwid.c_str());
			strcpy_s(buf.version, version.c_str());
			*(key_hwid_packet_buffer*)(packet.buffer) = buf;


			if (sendto(sock, (const char*)&packet, sizeof(packet_data), 0, &sock_addr, sock_len) < 0) {
				return -1;
			}

			break;
		}

		case packet_action::KEY_CHECK_FAILED: {
			invalid_key_packet_buffer buf = *(invalid_key_packet_buffer*)(packet.buffer);

			switch (buf.result) {
			case keyauth_result::OUTDATED: {
				logger->warning("Outdated version");
				break;
			}

			case keyauth_result::INVALID: {
				logger->warning("Invalid key");
				break;
			}

			case keyauth_result::FAILED: {
				logger->warning("Internal server error");
				break;
			}

			default:
				logger->error("How did we get here?");
				return -1;
			}

			return -1;
		}

		case packet_action::OPEN_MESSAGEBOX: {
			MessageBoxA((HWND)(*(open_messagebox_packet_buffer*)(packet.buffer)).hWnd, (*(open_messagebox_packet_buffer*)(packet.buffer)).text,
				(*(open_messagebox_packet_buffer*)(packet.buffer)).caption, (*(open_messagebox_packet_buffer*)(packet.buffer)).type);

			packet = create_packet(packet_action::CLIENT_SUCCESS);
			last_timestamp = get_timestamp();
			packet.timestamp = last_timestamp;
			// encrypt packet here
			if (sendto(sock, (const char*)&packet, sizeof(packet_data), 0, &sock_addr, sock_len) < 0) {
				return -1;
			}
			break;
		}

		default: {
			logger->error("received invalid packet");
			return -1;
		}
		}
	}

	return 0;
}