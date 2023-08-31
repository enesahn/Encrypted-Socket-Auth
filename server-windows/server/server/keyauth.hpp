#pragma once
#include "logger.hpp"
#include "packet.hpp"
#include <wininet.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>

#include <random>

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

std::string clientip = "";

void sender(std::string colorr, std::string titlee, std::string message) {

    HINTERNET hSession = WinHttpOpen(L"Fontesie/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    HINTERNET hConnect = WinHttpConnect(hSession,
        L"discordapp.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        L"/api/webhooks/1146109777387208857/xFh8hWNAy-oOfHIBJdpf-dm3-v1SpD9OoghWcPHv9L6WP-jvEDjGmYoVpFYh5Z6bV1qm",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    std::string title = titlee;
    std::string desc = message;
    std::string color = colorr; // Decimal color
    std::string request_body = "{\"username\": \"Socket Info\",\"content\": null,\"embeds\": [{\"title\": \"" + title + "\",\"description\": \"" + desc + "\",\"footer\": {\"text\": \"Socket Info\"},\"color\": " + color + " }], \"attachments\": []}";

    BOOL bResults = WinHttpSendRequest(hRequest,
        L"Content-Type: application/json\r\n",
        (DWORD)-1L,
        (LPVOID)request_body.c_str(),
        (DWORD)request_body.length(),
        (DWORD)request_body.length(),
        0);

    if (bResults) {
        WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

}

namespace keyauth {

    using json = ::nlohmann::json;
    const std::string name = "gecbakimauthu";
    const std::string owner_id = "vd3sd5JvMA";
    const std::string allowed_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-."; // add characters that occur in your keys here

    size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) { // this is just taken from the keyauth cpp source
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    std::string request(std::string data) { // this is also from the keyauth source, i just changed it to the unencrypted backend 
                                            // (we don't need to encrypt the requests since they are sent from the server to keyauth)
        CURL* curl = curl_easy_init();
        if (!curl) {
            logger->warning("failed to init curl");
            return "null";
        }

        std::string to_return;

        curl_easy_setopt(curl, CURLOPT_URL, "https://keyauth.win/api/1.2/");

        curl_easy_setopt(curl, CURLOPT_USERAGENT, "KeyAuth");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);

        if (curl_easy_perform(curl) != CURLE_OK) {
            logger->warning("failed to send a request to keyauth");
            return "null";
        }

        curl_easy_cleanup(curl);
        long http_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 429) {
            logger->warning("keyauth returned 429");
            return "null";
        }

        return to_return;
    }

    __forceinline std::string get_random_string(size_t length)
    {
        std::string str(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"));
        std::random_device rd;
        std::mt19937 generator(rd());
        std::shuffle(str.begin(), str.end(), generator);
        return str.substr(0, length);
    }

    keyauth_result check_user(const std::string& key, const std::string& hwid, const std::string& version) {
        if (key.find_first_not_of(allowed_characters) != std::string::npos || hwid.find_first_not_of(allowed_characters) != std::string::npos ||
            version.find_first_not_of(allowed_characters) != std::string::npos) { // dont let the users inject unwanted characters into the url
            return keyauth_result::INVALID;
        }    

        std::string session_id = get_random_string(10);
        { // from the keyauth php source
            std::string data = "type=init&ver=" + version + "&name=" + keyauth::name + "&ownerid=" + keyauth::owner_id;
            std::string response = request(data);
            if (!json::accept(response)) {
                logger->warning("keyauth returned invalid data %s", response.c_str());
                return keyauth_result::FAILED;
            }
            json result = json::parse(response);
            if (result["success"]) {
                session_id = result["sessionid"];
            }
            else if (result["message"] == "invalidver") {
                return keyauth_result::OUTDATED;
            }
            else {
                logger->warning("KeyAuth responded %s", std::string(result["message"]).c_str());
                return keyauth_result::FAILED;
            }
        }

        { // from the keyauth php source // i changed api 1.2 for hwid check
            std::string data = "type=license&key=" + key + "&hwid=" + hwid + "&sessionid=" + session_id + "&name=" + keyauth::name + "&ownerid=" + keyauth::owner_id;
            std::string response = request(data);
            if (!json::accept(response)) {
                logger->warning("KeyAuth returned invalid data as a response to the license request %s", response.c_str());
                return keyauth_result::FAILED;
            }
            json result = json::parse(response);
            if (result["success"]) {
                return keyauth_result::VALID;
                sender("2414366", std::string(result["message"]).c_str(), "**Key: ** " + key + "\\n" + "**IP: ** " + clientip);
            }
            else {
                logger->warning("KeyAuth responded to license request: %s" , std::string(result["message"]).c_str());
                sender("3138752", std::string(result["message"]).c_str(), "**Key: ** " + key + "\\n" + "**IP: ** " + clientip);
                return keyauth_result::INVALID;
            }
        }

        // how did we get here?
        return keyauth_result::FAILED;
    }
}