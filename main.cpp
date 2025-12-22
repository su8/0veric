/*
 * Copyright 12/22/2025 https://github.com/su8/0veric
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <readline/readline.h>
#include <readline/history.h>

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_RED     "\033[31m"

// Global channel list for tab-completion
std::vector<std::string> channels;

// Connect to IRC server via TCP
int tcpConnect(const std::string &server, int port);
// Send IRC command over SSL
void sendIRC(SSL *ssl, const std::string &cmd);
// Set file descriptor to non-blocking mode
void setNonBlocking(int fd);
// Tab-completion generator
char *channelNameGenerator(const char *text, int state);
// Completion function for Readline
char **channelCompletion(const char *text, int start, int end);
// Parse and colorize IRC messages
void parseAndPrintMessage(const std::string &msg);

int main(int argc, char *argv[]) {
  if (argc < 5) {
    std::cerr << "Usage: " << argv[0] << " <server> <port> <nick> <channel1> <channel2> ...\n";
    return EXIT_FAILURE;
  }

  std::string server = argv[1];
  int port = std::stoi(argv[2]);
  std::string nick = argv[3];
  std::string user = nick + " 0 * :" + nick;

  for (int x = 4; x < argc; x++) {
    channels.push_back(argv[x]);
  }

  // Setup Readline tab-completion
  rl_attempted_completion_function = channelCompletion;

  // Connect to IRC
  int sockfd = tcpConnect(server, port);
  if (sockfd < 0) return EXIT_FAILURE;

  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    close(sockfd);
    return EXIT_FAILURE;
  }

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
    return EXIT_FAILURE;
  }

  std::cout << COLOR_GREEN << "Connected securely to " << server << " via TLS.\n" << COLOR_RESET;

  // IRC handshake
  sendIRC(ssl, "NICK " + nick);
  sendIRC(ssl, "USER " + user);
  sleep(2);
  for (const auto &ch : channels) {
    sendIRC(ssl, "JOIN " + ch);
  }

  // Main loop: interactive with tab-completion
  char buffer[512] = {'\0'};
  while (true) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    struct timeval tv{0, 100000}; // 100ms
    int activity = select(sockfd + 1, &readfds, nullptr, nullptr, &tv);

    // Handle server messages
    if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
      std::memset(buffer, 0, sizeof(buffer));
      int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
      if (bytes <= 0) {
        std::cerr << COLOR_RED << "Disconnected from server.\n" << COLOR_RESET;
        break;
      }
      std::string msg(buffer);
      parseAndPrintMessage(msg);

      // Respond to PING
      if (msg.find("PING") == 0) {
        sendIRC(ssl, "PONG " + msg.substr(5));
      }
    }

    // Handle user input (blocking readline)
    char *line = readline("> ");
    if (!line) break; // EOF (Ctrl+D)

    std::string input(line);
    free(line);

    if (!input.empty()) {
      add_history(input.c_str());
    }

    if (input == "/quit") {
      sendIRC(ssl, "QUIT :Bye!");
      break;
    }
    else if (input.rfind("/join ", 0) == 0) {
      std::string newChannel = input.substr(6);
      sendIRC(ssl, "JOIN " + newChannel);
      channels.push_back(newChannel);
    }
    else if (input.rfind("/part ", 0) == 0) {
      std::string partChannel = input.substr(6);
      sendIRC(ssl, "PART " + partChannel);
      channels.erase(std::remove(channels.begin(), channels.end(), partChannel), channels.end());
    }
    else if (input.rfind("/msg ", 0) == 0) {
      size_t spacePos = input.find(' ', 5);
      if (spacePos != std::string::npos) {
        std::string targetChannel = input.substr(5, spacePos - 5);
        std::string message = input.substr(spacePos + 1);
        sendIRC(ssl, "PRIVMSG " + targetChannel + " :" + message);
      } else {
        std::cout << COLOR_YELLOW << "Usage: /msg #channel message" << COLOR_RESET << "\n";
      }
    }
    else if (!input.empty()) {
      // Send to all joined channels
      for (const auto &ch : channels) {
        sendIRC(ssl, "PRIVMSG " + ch + " :" + input);
      }
    }
  }

  // Cleanup
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(sockfd);

  return EXIT_SUCCESS;
}

// Connect to IRC server via TCP
int tcpConnect(const std::string &server, int port) {
  int sockfd;
  struct sockaddr_in serv_addr{};
  struct hostent *server_host;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Socket creation failed");
    return -1;
  }

  if ((server_host = gethostbyname(server.c_str())) == nullptr) {
    std::cerr << "No such host: " << server << std::endl;
    close(sockfd);
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  std::memcpy(&serv_addr.sin_addr.s_addr, server_host->h_addr, server_host->h_length);

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("Connection failed");
    close(sockfd);
    return -1;
  }

  return sockfd;
}

// Send IRC command over SSL
void sendIRC(SSL *ssl, const std::string &cmd) {
  std::string message = cmd + "\r\n";
  if (SSL_write(ssl, message.c_str(), message.size()) <= 0) {
    std::cerr << COLOR_RED << "SSL write failed.\n" << COLOR_RESET;
  }
}

// Set file descriptor to non-blocking mode
void setNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Tab-completion generator
char *channelNameGenerator(const char *text, int state) {
  static size_t list_index;
  static size_t len;

  if (!state) {
    list_index = 0;
    len = strlen(text);
  }

  while (list_index < channels.size()) {
    const std::string &name = channels[list_index++];
    if (name.compare(0, len, text) == 0) {
      return strdup(name.c_str());
    }
  }
  return nullptr;
}

// Completion function for Readline
char **channelCompletion(const char *text, int start, int end) {
  rl_attempted_completion_over = 1;

  // Only complete after /msg or /part
  if (start >= 5 && (strncmp(rl_line_buffer, "/msg ", 5) == 0 || strncmp(rl_line_buffer, "/part ", 6) == 0)) {
    return rl_completion_matches(text, channelNameGenerator);
  }
  return nullptr;
}

// Parse and colorize IRC messages
void parseAndPrintMessage(const std::string &msg) {
  if (msg.find("PING") == 0) {
    std::cout << COLOR_YELLOW << "[Server PING]" << COLOR_RESET << "\n";
    return;
  }
  if (msg.find("PRIVMSG") != std::string::npos) {
    size_t ex = msg.find('!');
    size_t col = msg.find(':', 1);
    if (ex != std::string::npos && col != std::string::npos) {
      std::string nick = msg.substr(1, ex - 1);
      std::string text = msg.substr(col + 1);
      std::cout << COLOR_CYAN << "<" << nick << "> " << COLOR_RESET << text << "\n";
      return;
    }
  }
  if (msg.find("JOIN") != std::string::npos) {
    size_t ex = msg.find('!');
    if (ex != std::string::npos) {
      std::string nick = msg.substr(1, ex - 1);
      std::cout << COLOR_GREEN << "[JOIN] " << nick << COLOR_RESET << "\n";
      return;
    }
  }
  if (msg.find("PART") != std::string::npos) {
    size_t ex = msg.find('!');
    if (ex != std::string::npos) {
      std::string nick = msg.substr(1, ex - 1);
      std::cout << COLOR_MAGENTA << "[PART] " << nick << COLOR_RESET << "\n";
      return;
    }
  }
  std::cout << msg;
}