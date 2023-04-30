#include <iostream>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>
#include <sys/stat.h>
#include <iomanip>
#include <sys/user.h>
#include <fcntl.h>
#include <bit>


#include "gdbserver.h"

using namespace std;

// Code structure from GPT-4
// GDB server implementation based on 
// https://medium.com/swlh/implement-gdb-remote-debug-protocol-stub-from-scratch-1-a6ab2015bfc5

pthread_mutex_t command_mutex;
pthread_cond_t command_cond;
bool command_ready = false;
GdbCommand current_command;
GdbResponse current_response;

#define PACKET_SIZE 0x47ff

// Escape a string according to GDB's RSP. Include F%x; at the start of the string
std::pair<std::size_t, std::string> gdb_binary_escape(const std::string& x, std::size_t count, char prefix) {
    string out = (std::stringstream() << prefix << std::hex << count << ";").str();
    std::size_t olen = out.length();
    for (char c : x) {
        if (std::string("$#}*").find(c) != std::string::npos) {
            if (out.length() + 2 > count) {
                // No room
                break;
            }
            out += '}';
            out += static_cast<char>(c ^ 0x20);
        } else {
            if (out.length() + 1 > count) {
                // No room
                break;
            }
            out += c;
        }
        olen += 1;
    }
    return {olen, out};
}

// GPT-4 rewrite of gdbserver's function by the same name
int hostio_reply_with_data(char *own_buf, const char *buffer, int len, int *new_packet_len) {
    const int kMaxOutputLength = 1024; // Set a maximum length to avoid buffer overflow
    int input_index = 0, output_index = 0;

    // Write the length of the output packet in hex
    output_index += snprintf(own_buf, kMaxOutputLength, "F%02x;", len);

    // Iterate over each byte of the input buffer and escape certain characters
    for (input_index = 0; input_index < len; input_index++) {
        char b = buffer[input_index];

        if (b == '$' || b == '#' || b == '}' || b == '*') {
            // Escape these characters
            if (output_index + 2 > kMaxOutputLength) {
                break; // Output buffer is full
            }
            own_buf[output_index++] = '}';
            own_buf[output_index++] = b ^ 0x20;
        } else {
            // Write the byte as is
            if (output_index + 1 > kMaxOutputLength) {
                break; // Output buffer is full
            }
            own_buf[output_index++] = b;
        }
    }

    // Set the length of the output packet
    *new_packet_len = output_index;

    // Return the number of bytes read from the input buffer
    return input_index;
}


GdbResponse handle_ptrace_command(pid_t debugee_pid, const GdbCommand& command) {
    GdbResponse response("");

    cout <<"Handling command " << command.payload << "\t-->\t"<< command.command << "(";
    // Print each in command.args
    for (auto arg : command.args) {
        cout << arg << " ";
    }
    cout << ")" << endl;

    switch (command.command) {
        case 'm': // Read memory
            {
                unsigned long long from_address = std::stoull(command.args[0], nullptr, 16);
                unsigned long long length = std::stoull(command.args[1], nullptr, 16);

                // Allocate a buffer to hold the memory read from the debugee
                std::vector<unsigned char> buf(length);
                bool error = false;

                // Read the memory from the debugee word by word
                for (size_t i = 0; i < length; i += sizeof(long)) {
                    long ret = ptrace(PTRACE_PEEKDATA, debugee_pid, reinterpret_cast<void*>(from_address + i), nullptr);
                    if (ret == -1 && errno != 0) {
                        // An error occurred
                        response = GdbResponse("E01");
                        error = true;
                        break;
                    }
                    // Copy the memory read from the debugee into the buffer
                    memcpy(buf.data() + i, &ret, std::min(sizeof(long), (unsigned long)length - i));
                }

                if (error) {
                    break;
                }

                // Convert the buffer to a hex-encoded string
                std::stringstream buffer;
                buffer << std::hex << std::setfill('0');
                for (unsigned char byte : buf) {
                    buffer << std::setw(2) << static_cast<unsigned int>(byte);
                }

                response = GdbResponse(buffer.str());
            }
            break;

        case 'M': // Write memory
        {
            unsigned long long address = std::stoull(command.args[0], nullptr, 16);
            unsigned long long length = std::stoull(command.args[1], nullptr, 16);
            std::string payload = command.args[2];

            std::vector<unsigned char> data;
            for (size_t i = 0; i < payload.length(); i += 2) {
                data.push_back(static_cast<unsigned char>(std::stoul(payload.substr(i, 2), nullptr, 16)));
            }

            for (size_t i = 0; i < length; i += sizeof(long)) {
                long word = 0;
                memcpy(&word, &data[i], std::min(sizeof(long), (size_t)length - i));
                if (ptrace(PTRACE_POKEDATA, debugee_pid, reinterpret_cast<void *>(address + i), reinterpret_cast<void *>(word)) == -1) {
                    response = GdbResponse("E01");
                    break;
                }
            }

            response = GdbResponse("OK");
        }
        break;

        case 'X': // Write memory (binary format)
        {
            unsigned long long address = std::stoull(command.args[0], nullptr, 16);
            unsigned long long length = std::stoull(command.args[1], nullptr, 16);
            std::string payload = command.args[2];

            std::vector<unsigned char> data;
            data.reserve(payload.size());
            for (size_t i = 0; i < payload.size(); ++i) {
                if (payload[i] == 0x7d) { // escape character
                    ++i;
                    data.push_back(payload[i] ^ 0x20);
                } else {
                    data.push_back(payload[i]);
                }
            }

            for (size_t i = 0; i < length; i += sizeof(long)) {
                long word = 0;
                memcpy(&word, &data[i], std::min(sizeof(long), (size_t)length - i));
                if (ptrace(PTRACE_POKEDATA, debugee_pid, reinterpret_cast<void *>(address + i), reinterpret_cast<void *>(word)) == -1) {
                    response = GdbResponse("E01");
                    break;
                }
            }

            response = GdbResponse("OK");
        }
        break;

        case 's': // Step
        {
            if (ptrace(PTRACE_SINGLESTEP, debugee_pid, nullptr, nullptr) == -1) {
                response = GdbResponse("E01");
                break;
            }

            // Wait for the debugee to stop
            int status;
            waitpid(debugee_pid, &status, 0);

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                response = GdbResponse("S05");
            } else {
                response = GdbResponse("E01");
            }
        }
        break;

        case 'c': // Continue
            // Implement the handling of the 'c' command using PTRACE API
            if (ptrace(PTRACE_CONT, debugee_pid, nullptr, nullptr) == -1) {
                response = GdbResponse("E01");
                break;
            }
            response = GdbResponse("OK");
            break;

        case 'T': // Is thread alive?
            {
                unsigned long long pid = std::stoull(command.args[0], nullptr, 16);
                if (pid == debugee_pid) {
                    response = GdbResponse("OK");
                } else {
                    response = GdbResponse("E01"); // Could actually do better
                }
            }
            break;

        case 'g': {
                struct user_regs_struct regs;

                if (ptrace(PTRACE_GETREGS, debugee_pid, nullptr, &regs) == -1) {
                    response = GdbResponse("E01");
                    break;
                }

                    std::vector<std::pair<unsigned long*, size_t>> reg_data;
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rax), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rbx), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rcx), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rdx), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rsi), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rdi), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rbp), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rsp), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r8),  8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r9),  8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r10), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r11), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r12), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r13), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r14), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.r15), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.rip), 8));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.eflags), 4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.cs),     4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.ss),     4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.ds),     4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.es),     4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.fs),     4));
                    reg_data.push_back(std::make_pair(reinterpret_cast<unsigned long*>(&regs.gs),     4));


                std::stringstream buffer;
                for (const auto& [reg, size] : reg_data) {
                    // Get a pointer to the bytes of the register
                    unsigned char* reg_bytes = reinterpret_cast<unsigned char*>(reg);

                    // Send the register value in little-endian byte order. We don't really support big-endian hosts so this is kinda pointless
                    if constexpr (std::endian::native == std::endian::big) {
                        std::reverse(reg_bytes, reg_bytes + size);
                    }
                    for (size_t i = 0; i < size; ++i) {
                        buffer << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(reg_bytes[i]);
                    }
                }
                response = GdbResponse(buffer.str());
            }
            break;

        case '?': // Last signal - lie and say we stopped due to a SIGTRAP
            {
                //self.writePacket(f"T05 swbreak;thread:{self.thread_id()};".encode())
                std::string raw = (std::stringstream() << "T05swbreak;thread:" << std::hex << debugee_pid << ";").str();
                cout << "QUESTION: SENDING: " << raw << endl;
                response = GdbResponse(raw);
            }
            break;


        case 'H': // set the thread ID future requests will refer to - always just ours. TODO: support multiple threads?
            response = GdbResponse("OK");
            break;

        case 'q': // Query
            {
                // Determine the query type and handle it accordingly
                std::string query_type = command.args[0];

                cout << "q command: query_type is " << query_type << endl;

                if (query_type == "Symbol") {
                    response = GdbResponse("OK"); // ??

                } else if (query_type == "Attached") {
                    response = GdbResponse("0"); // If we add support for multiple threads, this will need to change

                } else if (query_type == "TStatus") {
                    // Blank response is good for status

                } else if (query_type == "Supported") {
                    //string raw = (std::stringstream() << "PacketSize=" << std::hex << PACKET_SIZE << ";qXfer:exec-file:read+;multiprocess+;qXfer:auxv:read+").str();
                    string raw = (std::stringstream() << "PacketSize=" << std::hex << PACKET_SIZE << ";qXfer:exec-file:read+;qXfer:auxv:read+").str(); // No multiprocessing please
                    response = GdbResponse(raw);

                } else if (query_type == "Xfer") {
                    if ((command.args[1] == "exec-file" || command.args[1] == "auxv") && command.args[2] == "read") {
                        // Note the 3rd arg seems to always be empty? Fourth contains offset,len
                        char *tok = strtok((char*)command.args[4].c_str(), ",");
                        int offset = std::stoi(tok, nullptr, 16);
                        tok = strtok(nullptr, ",");
                        int length = std::stoi(tok, nullptr, 16);
                        
                        cout << "Reading " << command.args[1] << " offset " << offset << " len " << length << endl;

                        // filename is /proc/<target>/{exe,auxv}. If we have annex that's our target, else it's our debugee_pid
                        string filename = "/proc/";
                        if (command.args[3] != "") {
                            int annex = std::stoi(command.args[3], nullptr, 16); // Should be empty
                            filename += std::to_string(annex);
                        }else {
                            filename += std::to_string(debugee_pid);
                        }
                        filename += ((command.args[1] == "exec-file") ? "/exe" : "/auxv");

                        std::string full_data;

                        if (command.args[1] == "exec-file") {
                            // Need to readlink in filename
                            char buffer[256];
                            ssize_t len = readlink(filename.c_str(), buffer, sizeof(buffer)-1);
                            if (len < 0) {
                                cerr << "Failed to readlink file: " << filename << std::endl;
                                response = GdbResponse("E01");
                                break;
                            }
                            full_data = string(buffer, len);
                            // Should return m + pathname if it doesn't all fit. But let's just assume it does
                            // so we return l + pathname
                            string data = "l" + full_data.substr(offset, length);
                            response = GdbResponse(data);

                        } else {
                            // Want to read the auxv file
                            ifstream file(filename);
                            if (!file.is_open()) {
                                cerr << "Failed to open file: " << filename << std::endl;
                                response = GdbResponse("E01");
                                break;
                            }
                            string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                            file.close();
                            full_data = contents;

                            // Respond with m + binary
                            size_t olen;
                            string raw;
                            tie(olen, raw) = gdb_binary_escape(full_data, length, 'l');

                            if (olen < length) {
                                // Re-encode to ensure that it fits
                                tie(olen, raw) = gdb_binary_escape(full_data, olen, 'l');
                            }
                            response = GdbResponse(raw);
                        }
                    } else {
                        cout << "Unsupported qXfer command: " << command.args[1] << endl;
                        response = GdbResponse("");
                    }
                }
                // Add more cases to handle other 'q' commands
            }
            break;

        case 'v': // Multi-letter command starting with 'v'
            {
                // Determine the command type and handle it accordingly
                std::string cmd_type = command.args[0];

                if (cmd_type == "Cont?") {
                    // Implement handling for 'vCont?'
                } else if (cmd_type == "Kill") {
                    // Implement handling for 'vKill'
                } else if (cmd_type == "MustReplyEmpty") {
                    // Our blank response is exactly what we want
                } else if (cmd_type == "File") {
                    if (command.args[1] == "setfs") {
                        if (command.args[2] == "0") {
                            // Docs say we should return 0 but empty worked better according to py docs
                            response = GdbResponse("F0"); // With this it *does* call open, matches the docs but not our original implementation
                            break;
                        }else {
                            cout << "Unsupported vFile setfs for non-zero: " << command.args[2] << endl;
                        }
                    } else if (command.args[1] == "open") {
                        // Open the file specified args
                        // Arg 2 contains hex(fname),flags,mode. Let's split
                        vector<string> sub_args = split_string(command.args[2], string(","));

                        // Decode filename
                        stringstream ss;
                        for (size_t i = 0; i < sub_args[0].length(); i += 2) {
                            string byte_string = sub_args[0].substr(i, 2);
                            unsigned char byte = static_cast<unsigned char>(std::stoul(byte_string, nullptr, 16));
                            ss << byte;
                        }
                        string filename = ss.str();

                        int flags = std::stoi(sub_args[1].c_str(), nullptr, 16);
                        int mode = std::stoi(sub_args[2].c_str(), nullptr, 16);

                        bool is_target = filename.starts_with("target:");
                        if (is_target) filename = filename.at(strlen("target:"));

                        cout << "Open file target:" << is_target << ", name:" << filename << " flags " << flags << " mode " << mode << endl;

                        int fd = open(filename.c_str(), flags, mode);
                        if (fd < 0) {
                            std::cerr << "Failed to open file: " << filename << std::endl;
                            string raw = (std::stringstream() << "F-1,-" << std::hex << (-1*fd)).str(); // We want like -1 not ffffffff, so flip the sign and add a - in front
                            response = GdbResponse(raw); // Include errno
                        } else {
                            response = GdbResponse("F" + std::to_string(fd));
                        }
                    } else if (command.args[1] == "pread") {
                        vector<string> sub_args = split_string(command.args[2], string(","));
                        // fd,count,offset
                        int fd = std::stoi(sub_args[0].c_str(), nullptr, 16);
                        int count = std::stoi(sub_args[1].c_str(), nullptr, 16);
                        int offset = std::stoi(sub_args[2].c_str(), nullptr, 16);

                        // Seek fd to offset
                        lseek(fd, offset, SEEK_SET);
                        // Read up to count bytes from fd
                        char *buffer = new char[count]; // Previously this was char buffer[count] .. and it was somehow working(??)
                        int read_bytes = read(fd, buffer, count);
                        cout << "Tried to read " << std::hex << count << " bytes from fd " << fd << " at offset " << offset << " got " << read_bytes << std::dec << endl;
                        if (read_bytes < 0) {
                            std::cerr << "Failed to read from file: " << fd << std::endl;
                            response = GdbResponse("F-1"); // or E01?
                        } else {
                            // Respond with F + binary data
                            string file_data = string(buffer, read_bytes);
                            size_t olen;
                            string raw;
                            tie(olen, raw) = gdb_binary_escape(file_data, count, 'F');

                            if (olen < count) {
                                // Re-encode to ensure that it fits
                                tie(olen, raw) = gdb_binary_escape(file_data, olen, 'F');

                                if (olen >= count) {
                                    cout << "AHHHHHHHHHHHHH BAD" << endl;
                                }
                            }

                            response = GdbResponse(raw);
                            //cout << "Sending response:\n" << raw << endl;
                        }
                        delete[] buffer;

                    } else if (command.args[1] == "close") {
                        int rv = close(std::stoi(command.args[2].c_str(), nullptr, 16));
                        if (rv < 0) {
                            cerr << "Failed to close file for fd " << command.args[2] << std::endl;
                            response = GdbResponse("F-1");
                        } else {
                            response = GdbResponse("F0");
                        }

                    } else {
                        cout << "Unsupported vFile command: " << command.args[1] << endl;
                    }
                } else {
                    // Add more cases to handle other 'v' commands
                    cout << "Unsupported v command: " << cmd_type << endl;
                }
            }
            break;

        // Add more cases to handle other GDB commands

        default:
            // Send an empty response or an error message for unsupported commands
            cout << "Unsupported command: " << command.command << endl;
            break;
    }

    //cout << "Sending response: " << response.payload << endl;
    return response;
}


void* ptrace_thread(void* arg) {
    pid_t debugee_pid = *(pid_t*) arg;

    ptrace(PTRACE_ATTACH, debugee_pid, nullptr, nullptr);
    waitpid(debugee_pid, nullptr, 0);

    while (true) {
        pthread_mutex_lock(&command_mutex);

        while (!command_ready) {
            pthread_cond_wait(&command_cond, &command_mutex);
        }

        // Process the command using PTRACE API
        current_response = handle_ptrace_command(debugee_pid, current_command);

        command_ready = false;
        pthread_cond_signal(&command_cond);
        pthread_mutex_unlock(&command_mutex);
    }
}

void* gdb_thread(void* arg) {
    int port = 1234;
    if (getenv("HP_PORT") != NULL && atoi(getenv("HP_PORT")) != 0) {
      port = atoi(getenv("HP_PORT"));
    } else {
      printf("WARN: environ var HP_PORT not set using default %d\n", port);
    }
    GdbServer gdb_server(port);


    GdbCommand command;
    while (true) {
        cout << endl;
        try {
            command = gdb_server.receive_command();
        } catch (const std::runtime_error& e) {
            cerr << "Error: " << e.what() << endl;
            continue;
        }

        pthread_mutex_lock(&command_mutex);
        current_command = command;
        command_ready = true;
        pthread_cond_signal(&command_cond);

        while (command_ready) {
            pthread_cond_wait(&command_cond, &command_mutex);
        }

        gdb_server.send_response(current_response.payload);
        pthread_mutex_unlock(&command_mutex);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <debugee_pid>" << endl;
        return 1;
    }

    pid_t debugee_pid = stoi(argv[1]);

    pthread_t gdb_tid, ptrace_tid;
    pthread_mutex_init(&command_mutex, nullptr);
    pthread_cond_init(&command_cond, nullptr);

    pthread_create(&gdb_tid, nullptr, gdb_thread, nullptr);
    pthread_create(&ptrace_tid, nullptr, ptrace_thread, &debugee_pid);

    pthread_join(gdb_tid, nullptr);
    pthread_join(ptrace_tid, nullptr);

    pthread_mutex_destroy(&command_mutex);
    pthread_cond_destroy(&command_cond);

    return 0;
}
