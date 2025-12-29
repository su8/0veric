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
#include <sstream>
#include <fstream>
#include <ctime>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <mutex>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <readline/readline.h>
#include <readline/history.h>

std::atomic<bool> running(true);
std::mutex coutMutex;

// Global pointers for readline callback
SSL *global_ssl = nullptr;
struct Config *global_cfg = nullptr;

struct Config {
  std::string server = "irc.libera.chat";
  int port = 6697;
  std::string nick = "Lunnis";
  std::string user = "Lunnis 0 * :GNU IRC Client";
  std::vector<std::string> channels = {"#ubuntu"};
  std::string logFile = "/tmp/0veric.log";
  std::string activeChannel = "#ubuntu";
};

struct IRCMessage {
  std::string prefix;
  std::string command;
  std::vector<std::string> params;
};

std::string timestamp(void);
void logToFile(const std::string &filename, const std::string &line);
IRCMessage parseIRCMessage(const std::string &raw);
int connectToServer(const std::string &server, int port);
SSL_CTX *initSSL(void);
void sendIRC(SSL *ssl, const std::string &cmd);
void handleMessage(const IRCMessage &msg, SSL *ssl, const Config &cfg);
bool loadConfig(Config &cfg);
void handleSigint(int);
void inputHandler(char *input);

int main(void) {
  signal(SIGINT, handleSigint);
  Config cfg;
  loadConfig(cfg);
  global_cfg = &cfg;
  std::string nickServ = getenv("NICKSERV_PASSWORD") ? static_cast<std::string>(getenv("NICKSERV_PASSWORD")) : static_cast<std::string>("");
  while (running) {
    int sockfd = connectToServer(cfg.server, cfg.port);
    if (sockfd < 0) {
      std::cerr << "[" << timestamp() << "] Retry in 5 seconds...\n";
      sleep(5);
      continue;
    }
    SSL_CTX *ctx = initSSL();
    if (!ctx) {
      close(sockfd);
      break;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(sockfd);
      sleep(5);
      continue;
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
      std::cerr << "Error: No certificate presented by server." << std::endl;
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(sockfd);
      sleep(5);
      continue;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
      std::cerr << "Error: certificate verification failed." << std::endl;
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(sockfd);
      sleep(5);
      continue;
    }
    std::cout << "SSL connection established and certificate verified." << std::endl;
    global_ssl = ssl;
    {
      std::lock_guard<std::mutex> lock(coutMutex);
      std::cout << "[" << timestamp() << "] Connected to " << cfg.server << " with " << SSL_get_cipher(ssl) << " encryption.\n";
    }
    // IRC handshake
    sendIRC(ssl, "NICK " + cfg.nick);
    sendIRC(ssl, "USER " + cfg.user);
    sleep(2);
    for (const auto &chan : cfg.channels) {
      sendIRC(ssl, "JOIN " + chan);
    }
    // Setup readline
    rl_callback_handler_install("> ", inputHandler);
    fd_set readfds;
    struct timeval tv;
    char buffer[512] = {'\0'};
    bool identified = false;
    while (running) {
      FD_ZERO(&readfds);
      int ssl_fd = SSL_get_fd(ssl);
      FD_SET(ssl_fd, &readfds);
      FD_SET(STDIN_FILENO, &readfds);
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      int activity = select(std::max(ssl_fd, STDIN_FILENO) + 1, &readfds, nullptr, nullptr, &tv);
      if (activity < 0 && running) {
        perror("select");
        break;
      }
      // Server messages
      if (FD_ISSET(ssl_fd, &readfds)) {
        std::memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
          std::lock_guard<std::mutex> lock(coutMutex);
          std::cerr << "[" << timestamp() << "] Connection closed by server.\n";
          break;
        }
        std::cout << buffer << std::endl;
        if (!nickServ.empty()) {
          std::string data(buffer);
          if (!identified && data.rfind("End of /MOTD") != std::string::npos) {
            sendIRC(global_ssl, "PRIVMSG NickServ :IDENTIFY " + nickServ);
            identified = true;
          }
          if (identified && data.rfind("You are now identified") != std::string::npos) {
            sendIRC(global_ssl, "PRIVMSG " + cfg.activeChannel + " : Hello form a secure, verified TLS IRC client!");
          }
        }
        std::istringstream stream(buffer);
        std::string line;
        while (std::getline(stream, line)) {
          if (line.empty()) continue;
          if (line.back() == '\r') line.pop_back();
          IRCMessage msg = parseIRCMessage(line);
          handleMessage(msg, ssl, cfg);
        }
      }
      // User input
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        rl_callback_read_char();
      }
    }
    rl_callback_handler_remove();
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
    if (running) {
      std::cerr << "[" << timestamp() << "] Reconnecting in 5 seconds...\n";
      sleep(5);
    }
  }
  return EXIT_SUCCESS;
}

void inputHandler(char *input) {
  if (!input) {
    running = false;
    return;
  }
  std::string cmd(input);
  free(input);
  if (cmd.empty()) return;
  add_history(cmd.c_str());
  if (cmd == "/quit") {
    sendIRC(global_ssl, "QUIT :Bye!");
    running = false;
  } else if (cmd.rfind("/join ", 0) == 0) {
    sendIRC(global_ssl, "JOIN " + cmd.substr(6));
    global_cfg->channels.push_back(cmd.substr(6));
    global_cfg->activeChannel = cmd.substr(6);
  } else if (cmd.rfind("/switch ", 0) == 0) {
    std::string chan = cmd.substr(8);
    for (auto &c : global_cfg->channels) {
      if (c == chan) {
        global_cfg->activeChannel = chan;
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "[" << timestamp() << "] *** Switched to " << chan << "\n";
        return;
      }
    }
    std::lock_guard<std::mutex> lock(coutMutex);
    std::cout << "[" << timestamp() << "] *** Not in channel " << chan << "\n";
  } else if (cmd.rfind("/msg ", 0) == 0) {
    std::istringstream iss(cmd.substr(5));
    std::string target;
    iss >> target;
    std::string text;
    std::getline(iss, text);
    if (!text.empty() && text[0] == ' ') text.erase(0, 1);
    sendIRC(global_ssl, "PRIVMSG " + target + " :" + text);
  } else {
    // Default: send to active channel
    sendIRC(global_ssl, "PRIVMSG " + global_cfg->activeChannel + " :" + cmd);
  }
}


void handleSigint(int) {
  running = false;
  std::lock_guard<std::mutex> lock(coutMutex);
  std::cout << "\n[" << timestamp() << "] *** Caught SIGINT, exiting...\n";
}

bool loadConfig(Config &cfg) {
  std::ifstream file((getenv("HOME") ? static_cast<std::string>(getenv("HOME")) + static_cast<std::string>("/") : static_cast<std::string>("./")) + ".0veric.conf");
  if (!file) return false;
  std::string key, value;
  while (file >> key >> value) {
    if (key == "server") cfg.server = value;
    else if (key == "port") cfg.port = std::stoi(value);
    else if (key == "nick") cfg.nick = value;
    else if (key == "channel") cfg.channels.push_back(value);
    else if (key == "logfile") cfg.logFile = value;
  }
  if (!cfg.channels.empty()) cfg.activeChannel = cfg.channels[0];
  return true;
}

void handleMessage(const IRCMessage &msg, SSL *ssl, const Config &cfg) {
  if (msg.command == "PING" && !msg.params.empty()) {
    sendIRC(ssl, "PONG :" + msg.params[0]);
  } else if (msg.command == "PRIVMSG" && msg.params.size() >= 2) {
    std::string user = msg.prefix.substr(0, msg.prefix.find('!'));
    std::string channel = msg.params[0];
    std::string text = msg.params[1];
    std::lock_guard<std::mutex> lock(coutMutex);
    rl_on_new_line();
    rl_redisplay();
    std::cout << "\r[" << timestamp() << "] [" << channel << "] <" << user << "> " << text << "\n";
    rl_on_new_line();
    rl_redisplay();
    logToFile(cfg.logFile, "[" + channel + "] <" + user + "> " + text);
  } else {
    logToFile(cfg.logFile, "[RAW] " + msg.command);
  }
}

void sendIRC(SSL *ssl, const std::string &cmd) {
  std::string message = cmd + "\r\n";
  if (SSL_write(ssl, message.c_str(), message.size()) <= 0) {
    ERR_print_errors_fp(stderr);
  }
}

SSL_CTX *initSSL(void) {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_default_verify_paths(ctx);
  return ctx;
}

int connectToServer(const std::string &server, int port) {
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

IRCMessage parseIRCMessage(const std::string &raw) {
  IRCMessage msg;
  std::istringstream iss(raw);
  std::string token;
  if (!raw.empty() && raw[0] == ':') {
    iss >> token;
    msg.prefix = token.substr(1);
  }
  if (iss >> token) {
    msg.command = token;
  }
  while (iss >> token) {
    if (token[0] == ':') {
      std::string trailing = token.substr(1);
      std::string rest;
      std::getline(iss, rest);
      trailing += rest;
      msg.params.push_back(trailing);
      break;
    } else {
      msg.params.push_back(token);
    }
  }
  return msg;
}

std::string timestamp(void) {
  std::time_t now = std::time(nullptr);
  char buf[128] = {'\0'};
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
  return std::string(buf);
}

void logToFile(const std::string &filename, const std::string &line) {
  std::ofstream out(filename, std::ios::app);
  if (out) out << "[" << timestamp() << "] " << line << "\n";
}