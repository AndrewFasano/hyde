#include "gdbserver.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

using namespace std;

std::vector<std::string> split_string(std::string payload, std::string delimiter) {
    std::vector<std::string> args; // Local var
    size_t start = 0, end = 0;
    while ((end = payload.find(delimiter, start)) != std::string::npos) {
        std::string arg = payload.substr(start, end - start);
        args.push_back(arg);
        start = end + 1;
    }
    std::string arg = payload.substr(start);
    args.push_back(arg);

    // If no matches, add everything after the first character
    if (args.empty()) {
        args.push_back(payload.substr(1));
    }
    return args;
}

GdbServer::GdbServer(int gdb_port) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        throw runtime_error("Failed to create socket");
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(gdb_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        close(server_fd);
        throw runtime_error("Failed to bind socket");
    }

    if (listen(server_fd, 1) == -1) {
        close(server_fd);
        throw runtime_error("Failed to listen on socket");
    }

    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_addr_len);
    if (client_fd == -1) {
        close(server_fd);
        throw runtime_error("Failed to accept connection");
    }
}

GdbServer::~GdbServer() {
    close(client_fd);
    close(server_fd);
}


string GdbServer::receive_packet() {
    string packet;
    bool gdbcommand = false;
    int csum = 0;
    char c;

    while (true) {
        if (read(client_fd, &c, 1) != 1) {
            // We finished reading, but we didn't get a checksum - invalid packet
            send(client_fd, "-", 1, 0); // NACK? Maybe?
            return "";
        }
        if (c == '\x03') {
            // Got Ctrl-c from client?
            throw std::runtime_error("Client disconnected");
            break;
        }
        if (gdbcommand) {
            if (c == '#') {
                char checksum_str[3];
                if (read(client_fd, checksum_str, 2) != 2) {
                    throw std::runtime_error("Error reading checksum");
                }
                checksum_str[2] = '\0';
                int checksum = std::stoi(checksum_str, nullptr, 16);
                if (csum != checksum) {
                    throw std::runtime_error("Bad checksum");
                }
                break;
            } else {
                // Compute checksum as we go
                packet += c;
                csum = (csum + static_cast<unsigned char>(c)) % 256;
            }
        } else if (c == '$') {
            gdbcommand = true;
        }
    }

    //cout << "Received full packet:" << packet << endl;

    // We didn't raise any issues - send an ack
    //send(client_fd, "+", 1, 0);
    return packet;
}

void GdbServer::send_packet(const std::string& payload) {
    // TODO: should we ack everything? Seems like real gdbserver only acks a few things
    unsigned int checksum = 0;
    for (char ch : payload) {
        checksum += static_cast<unsigned char>(ch);
    }
    checksum %= 256;

    stringstream ss;
    ss << "+$" << payload << "#" << setw(2) << setfill('0') << hex << checksum;

    string packet = ss.str();
    cout << "Sending full packet:" << packet << endl;
    send(client_fd, packet.c_str(), packet.length(), 0);
}


GdbCommand GdbServer::receive_command() {
    string packet = receive_packet();
    return GdbCommand(packet);
}


void GdbServer::send_response(const GdbResponse& response) {
    send_packet(response.payload);
}