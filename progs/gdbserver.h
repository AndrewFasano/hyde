#ifndef GDBSERVER_H
#define GDBSERVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <iostream>

#include <unordered_map>
#include <vector>

std::vector<std::string> split_string(std::string payload, std::string delimiter);

class GdbCommand {
public:
    std::string payload;
    char command;
    std::vector<std::string> args;

    GdbCommand() : payload("") {
        parse();
    }

    GdbCommand(const std::string& payload) : payload(payload) {
        parse();
    }

    // Copy constructor
    GdbCommand(const GdbCommand& other) {
        payload = other.payload;
        command = other.command;
        args = other.args;
        parse();
    }

    // Assignment operator overload
    GdbCommand& operator=(const GdbCommand& other) {
        if (this != &other) {
            payload = other.payload;
            command = other.command;
            args = other.args;
        }
        return *this;
    }


private:
    void parse() {
        if (!payload.empty()) {
            command = payload.at(0);
            parse_args();
        } else {
            command = '\0';
        }
    }

    void parse_args() {
        // Parse the arguments based on the command type
        std::string delimiter;

        switch (command) {
            case 'm': // Read memory
            case 'M': // Write memory
                delimiter = ",";
                break;
            case 'X': // Write memory (binary format)
            case 'q': // Query command
            case 'v':
                delimiter = ":";
                break;

            default:
                std::cout << "Unable to parse command: " << command << std::endl;
            case 'H': // These ones don't have arguments so we just handle them here
            case '?':
                if (payload.length() > 1) args.push_back(payload.substr(1)); // Pass all but first char as argument 0, ignore the rest
                return;
        }
        args = split_string(payload.substr(1), delimiter); // Skip first char in payload

    }
};

class GdbResponse {
public:
    std::string payload;

    GdbResponse() : payload("") {}

    GdbResponse(const std::string& payload) : payload(payload) {}

    // Copy constructor
    GdbResponse(const GdbResponse& other) {
        payload = other.payload;
    }

    // Assignment operator overload
    GdbResponse& operator=(const GdbResponse& other) {
        if (this != &other) {
            payload = other.payload;
        }
        return *this;
    }
};

class GdbServer {
private:
    int server_fd;
    int client_fd;

    std::string receive_packet();
    void send_packet(const std::string& payload);

public:
    GdbServer(int port);
    ~GdbServer();

    GdbCommand receive_command();
    void send_response(const GdbResponse& response);
};

#endif
