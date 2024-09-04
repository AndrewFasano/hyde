// Entirely written by gpt-3
// Binds port 80 as root, then drop privileges and listens for connections

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define PORT 80

int main() {
    // Verify that we are running as root
    if (getuid() != 0) {
        fprintf(stderr, "Error: must be run as root\n");
        exit(EXIT_FAILURE);
    }

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "Error setting socket option: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Bind to port 80 on all IPv4 interfaces
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = { .s_addr = INADDR_ANY }
    };
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Drop privileges
    if (setgid(65534) != 0 || setuid(65534) != 0) {
        fprintf(stderr, "Error dropping privileges: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(sockfd, 5) < 0) {
        fprintf(stderr, "Error listening on socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d...\n", PORT);

    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addrlen);
        if (clientfd < 0) {
            fprintf(stderr, "Error accepting connection: %s\n", strerror(errno));
            continue;
        }

        // Handle the connection
        char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello world!";
        send(clientfd, response, sizeof(response), 0);

        // Close the connection
        close(clientfd);
    }

    // Close the listening socket
    close(sockfd);

    return 0;
}
