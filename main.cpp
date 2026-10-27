/*
 * Copyright 10/12/2026 08/04/2026 12/22/2025 https://github.com/su8/0veric
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
#include <cctype>
#include <cerrno>
#include <atomic>
#include <mutex>
#include <memory>
#include <utility>
#include <unistd.h>
#include <netdb.h>
#include <algorithm>
#include <map>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <readline/readline.h>
#include <readline/history.h>

#define RESETCOLOUR "\033[0;0m"
#define BOLD_YELLOW "\033[1;33m"
#define MAGENTA "\033[1;35m"
#define GREY "\033[90m"

struct Config {
  std::string server = "irc.libera.chat";
  int port = 6697;
  std::string nick = "Lunnis";
  std::string user = "Lunnis";
  std::string realname = "GNU IRC Client";
  std::vector<std::string> channels = {"#ubuntu", "#debian"};
  std::string logFile = "/tmp/0veric.log";
  std::string activeChannel = "#ubuntu";
  bool colour = true;
};

struct IRCMessage {
  std::string prefix;
  std::string command;
  std::vector<std::string> params;
};

// State of one connection to the server
struct Session {
  std::string nickServ;   // NickServ password, empty if there is none
  bool joined = false;    // channels were joined after the welcome
  bool greeted = false;   // greeting after the NickServ identification was sent
};

// Closes the socket when the connection attempt ends, however it ends
struct Socket {
  int fd;
  explicit Socket(int f) : fd(f) {}
  ~Socket() { if (fd >= 0) { close(fd); } }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

std::atomic<bool> running(true);
std::mutex coutMutex;

// Global pointers for readline callback
SSL *global_ssl = nullptr;
Config *global_cfg = nullptr;
// Complete nick lists, the key is the lowercase channel name
std::map<std::string, std::vector<std::string>> channelNicks;
// 353 replies that wait for the 366 which ends the list
std::map<std::string, std::vector<std::string>> pendingNicks;
bool readlineActive = false;
bool showRaw = false;   // /debug prints every line from the server

std::string timestamp(void);
void logToFile(const std::string &filename, const std::string &line);
IRCMessage parseIRCMessage(const std::string &raw);
int connectToServer(const std::string &server, int port);
SSL_CTX *initSSL(void);
X509 *peerCertificate(SSL *ssl);
void sendIRC(SSL *ssl, std::string cmd);
bool readFromServer(SSL *ssl, std::string &inbuf);
void processInput(std::string &inbuf, SSL *ssl, Config &cfg, Session &session);
void handleMessage(const IRCMessage &msg, SSL *ssl, Config &cfg, Session &session);
bool runConnection(Config &cfg, const std::string &nickServ);
bool loadConfig(Config &cfg);
void handleSigint(int);
void inputHandler(char *input);
// Text helpers
std::string trimSpaces(const std::string &s);
std::string lower(std::string s);
bool iequals(const std::string &a, const std::string &b);
bool isChannelName(const std::string &name);
bool hasChannel(const Config &cfg, const std::string &name);
// Removes control characters and mIRC colour codes, so that the server can't send terminal escape sequences
std::string cleanText(const std::string &text);
bool mentions(const std::string &text, const std::string &nick);
// Colours
std::string paint(const char *code, const std::string &text);
std::string nickColour(const std::string &nick);
std::string channelColour(const std::string &channel);
std::string colouredChannel(const std::string &channel);
// Output
void printAbovePrompt(const std::string &line, bool inCallback = false);
void showChat(const std::string &label, const std::string &nick, const std::string &text, bool inCallback, bool highlight, bool action = false);
void showNotice(const std::string &text, bool inCallback = false);
// Collect the NAMES reply (353) and publish it at the end of the list (366)
void collectNames(const IRCMessage &msg);
void finishNames(const IRCMessage &msg);
// Readline completion generator
char *nicknameGenerator(const char* text, int state);
// Readline completion entry point
char **nicknameCompletion(const char* text, int start, int end);

int main(void) {
  signal(SIGINT, handleSigint);
  Config cfg;
  loadConfig(cfg);
  const char *noColour = std::getenv("NO_COLOR"); // https://no-color.org
  if (noColour && *noColour) { cfg.colour = false; }
  global_cfg = &cfg;
  const char *password = std::getenv("NICKSERV_PASSWORD");
  const std::string nickServ = password ? password : "";
  unsigned int failures = 0U;
  while (running) {
    if (runConnection(cfg, nickServ)) {
      failures = 0U;
      if (running) {
        std::cerr << "[" << timestamp() << "] Reconnecting in 5 seconds...\n";
        sleep(5);
      }
    } else {
      // 5, 10, 20, 40 and then 60 seconds between the attempts
      failures++;
      unsigned int delay = std::min(5U << std::min(failures - 1U, 4U), 60U);
      std::cerr << "[" << timestamp() << "] Retry in " << delay << " seconds...\n";
      sleep(delay);
    }
  }
  std::cout << "\n[" << timestamp() << "] *** Exiting...\n";
  return EXIT_SUCCESS;
}

// One connection: connect, verify the certificate, register and run until it ends.
// Returns false when the connection could not be established
bool runConnection(Config &cfg, const std::string &nickServ) {
  Socket sock(connectToServer(cfg.server, cfg.port));
  if (sock.fd < 0) { return false; }
  SslCtxPtr ctx(initSSL(), SSL_CTX_free);
  if (!ctx) { return false; }
  SslPtr ssl(SSL_new(ctx.get()), SSL_free);
  if (!ssl) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  SSL_set_fd(ssl.get(), sock.fd);
  // SNI, and the certificate must be valid for this host name, not just for any host
  SSL_set_tlsext_host_name(ssl.get(), cfg.server.c_str());
  if (SSL_set1_host(ssl.get(), cfg.server.c_str()) != 1) {
    std::cerr << "Error: could not set the host name to verify." << std::endl;
    return false;
  }
  if (SSL_connect(ssl.get()) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  X509Ptr cert(peerCertificate(ssl.get()), X509_free);
  if (!cert) {
    std::cerr << "Error: No certificate presented by server." << std::endl;
    return false;
  }
  if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
    std::cerr << "Error: certificate verification failed." << std::endl;
    return false;
  }
  std::cout << "SSL connection established and certificate verified." << std::endl;
  std::cout << "[" << timestamp() << "] Connected to " << cfg.server << " with " << SSL_get_cipher(ssl.get()) << " encryption.\n";
  global_ssl = ssl.get();
  // The nick lists belong to one connection
  channelNicks.clear();
  pendingNicks.clear();
  // IRC handshake
  sendIRC(ssl.get(), "NICK " + cfg.nick);
  sendIRC(ssl.get(), "USER " + cfg.user + " 0 * :" + cfg.realname);
  // Setup readline
  rl_attempted_completion_function = nicknameCompletion;
  rl_callback_handler_install("> ", inputHandler);
  readlineActive = true;
  Session session;
  session.nickServ = nickServ;
  std::string inbuf;
  fd_set readfds;
  const int sslFd = SSL_get_fd(ssl.get());
  while (running) {
    FD_ZERO(&readfds);
    FD_SET(sslFd, &readfds);
    FD_SET(STDIN_FILENO, &readfds);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int activity = select(std::max(sslFd, STDIN_FILENO) + 1, &readfds, nullptr, nullptr, &tv);
    if (activity < 0) {
      if (errno == EINTR) { continue; } // Ctrl+C: the loop condition ends the program
      perror("select");
      break;
    }
    // Server messages
    if (FD_ISSET(sslFd, &readfds)) {
      if (!readFromServer(ssl.get(), inbuf)) {
        printAbovePrompt("[" + timestamp() + "] Connection closed by server.");
        break;
      }
      processInput(inbuf, ssl.get(), cfg, session);
    }
    // User input
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      rl_callback_read_char();
    }
  }
  readlineActive = false;
  rl_callback_handler_remove();
  SSL_shutdown(ssl.get());
  global_ssl = nullptr;
  return true;
}

// Read everything that is available now; false when the connection is gone
bool readFromServer(SSL *ssl, std::string &inbuf) {
  char buffer[4096];
  do {
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
      int err = SSL_get_error(ssl, bytes);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { return true; }
      return false;
    }
    inbuf.append(buffer, static_cast<size_t>(bytes));
    // Data that OpenSSL already decrypted is not visible to select()
  } while (SSL_pending(ssl) > 0);
  return true;
}

// A read can end in the middle of a line: only complete lines are handled, the rest stays in the buffer
void processInput(std::string &inbuf, SSL *ssl, Config &cfg, Session &session) {
  size_t pos;
  while ((pos = inbuf.find('\n')) != std::string::npos) {
    std::string line = inbuf.substr(0, pos);
    inbuf.erase(0, pos + 1);
    if (!line.empty() && line.back() == '\r') { line.pop_back(); }
    if (line.empty()) { continue; }
    if (showRaw) { printAbovePrompt(paint(GREY, "[RAW] " + cleanText(line))); }
    handleMessage(parseIRCMessage(line), ssl, cfg, session);
  }
  if (inbuf.size() > 65536) { inbuf.clear(); } // a line that never ends
}

// Collect the NAMES reply (353): ":server 353 me = #channel :nick1 @nick2 +nick3"
// A long list arrives in several parts, so the nicks are kept until 366
void collectNames(const IRCMessage &msg) {
  if (msg.params.size() < 4) { return; }
  std::vector<std::string> &list = pendingNicks[lower(msg.params[2])];
  std::istringstream names(msg.params[3]);
  std::string nick;
  while (names >> nick) {
    size_t first = nick.find_first_not_of("~&@%+"); // all the status prefixes
    if (first == std::string::npos) { continue; }
    nick = nick.substr(first);
    nick = nick.substr(0, nick.find('!')); // userhost-in-names
    if (!nick.empty()) { list.push_back(nick); }
  }
}

// RPL_ENDOFNAMES (366): ":server 366 me #channel :End of /NAMES list."
void finishNames(const IRCMessage &msg) {
  if (msg.params.size() < 2) { return; }
  auto it = pendingNicks.find(lower(msg.params[1]));
  if (it == pendingNicks.end()) { return; }
  channelNicks[it->first] = std::move(it->second);
  pendingNicks.erase(it);
}

// Readline completion generator
char *nicknameGenerator(const char* text, int state) {
  static size_t list_index;
  static size_t len;
  static std::vector<std::string> matches;

  if (!state) { // First call
    list_index = 0;
    len = strlen(text);
    matches.clear();
    const std::string prefix = lower(text);
    auto it = channelNicks.find(lower(global_cfg->activeChannel));
    if (it != channelNicks.end()) {
      for (const auto &nick : it->second) {
        if (lower(nick).compare(0, len, prefix) == 0) {
          matches.push_back(nick);
        }
      }
    }
  }

  if (list_index < matches.size()) {
    return strdup(matches[list_index++].c_str());
  }
  return nullptr;
}

// Readline completion entry point
char **nicknameCompletion(const char* text, int start, int end) {
  (void)start; (void)end;
  rl_attempted_completion_over = 1; // no file names when there is no nick
  return rl_completion_matches(text, nicknameGenerator);
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
  } else if (cmd == "/list") {
    std::string text = "Joined to the following channel(s)";
    for (const auto &channel : global_cfg->channels) {
      text += "\n" + colouredChannel(channel);
    }
    printAbovePrompt(text, true);
  } else if (cmd == "/debug") {
    showRaw = !showRaw;
    printAbovePrompt(std::string("*** Raw server lines ") + (showRaw ? "ON" : "OFF"), true);
  } else if (cmd.rfind("/join ", 0) == 0) {
    std::string chan = trimSpaces(cmd.substr(6));
    if (!isChannelName(chan)) {
      printAbovePrompt("*** Usage: /join #channel", true);
      return;
    }
    sendIRC(global_ssl, "JOIN " + chan);
    if (!hasChannel(*global_cfg, chan)) { global_cfg->channels.push_back(chan); }
    global_cfg->activeChannel = chan;
  } else if (cmd.rfind("/switch ", 0) == 0) {
    std::string chan = trimSpaces(cmd.substr(8));
    for (auto &c : global_cfg->channels) {
      if (iequals(c, chan)) {
        global_cfg->activeChannel = c;
        printAbovePrompt("[" + timestamp() + "] *** Switched to " + colouredChannel(c), true);
        return;
      }
    }
    printAbovePrompt("[" + timestamp() + "] *** Not in channel " + cleanText(chan), true);
  } else if (cmd.rfind("/msg ", 0) == 0) {
    std::istringstream iss(cmd.substr(5));
    std::string target;
    iss >> target;
    std::string text;
    std::getline(iss, text);
    if (!text.empty() && text[0] == ' ') text.erase(0, 1);
    if (target.empty() || text.empty()) {
      printAbovePrompt("*** Usage: /msg target message", true);
      return;
    }
    sendIRC(global_ssl, "PRIVMSG " + target + " :" + text);
    // Show what was sent, the server doesn't send it back
    std::string label = isChannelName(target) ? colouredChannel(target) : paint(MAGENTA, "PM -> " + cleanText(target));
    showChat(label, global_cfg->nick, cleanText(text), true, false);
  } else if (cmd.rfind("/whois ", 0) == 0) {
    sendIRC(global_ssl, "WHOIS " + cmd.substr(7));
  } else {
    // Default: send to active channel
    if (global_cfg->activeChannel.empty()) {
      printAbovePrompt("*** No active channel, use /join #channel", true);
      return;
    }
    sendIRC(global_ssl, "PRIVMSG " + global_cfg->activeChannel + " :" + cmd);
    showChat(colouredChannel(global_cfg->activeChannel), global_cfg->nick, cleanText(cmd), true, false);
  }
}

// Only set the flag: a signal handler must not lock a mutex or print
void handleSigint(int) {
  running = false;
}

// One "key value" per line, # starts a comment, the value can contain spaces
bool loadConfig(Config &cfg) {
  const char *home = std::getenv("HOME");
  std::ifstream file((home ? std::string(home) + "/" : std::string("./")) + ".0veric.conf");
  if (!file) return false;
  bool channelsGiven = false;
  std::string line;
  while (std::getline(file, line)) {
    line = trimSpaces(line);
    if (line.empty() || line[0] == '#') continue;
    size_t split = line.find_first_of(" \t");
    if (split == std::string::npos) continue;
    std::string key = line.substr(0, split);
    std::string value = trimSpaces(line.substr(split));
    if (value.empty()) continue;
    if (key == "server") cfg.server = value;
    else if (key == "port") {
      try {
        int port = std::stoi(value);
        if (port < 1 || port > 65535) { throw std::out_of_range("port"); }
        cfg.port = port;
      } catch (const std::exception &) {
        std::cerr << "Invalid port '" << value << "' in .0veric.conf, using " << cfg.port << "\n";
      }
    }
    else if (key == "nick") cfg.nick = value;
    else if (key == "user") cfg.user = value;
    else if (key == "realname") cfg.realname = value;
    else if (key == "channel") {
      // The channels of the file replace the built-in default
      if (!channelsGiven) { cfg.channels.clear(); channelsGiven = true; }
      if (!hasChannel(cfg, value)) { cfg.channels.push_back(value); }
    }
    else if (key == "logfile") cfg.logFile = value;
    else if (key == "colour") cfg.colour = (value != "off" && value != "no" && value != "0");
  }
  if (!cfg.channels.empty()) cfg.activeChannel = cfg.channels[0];
  return true;
}

void handleMessage(const IRCMessage &msg, SSL *ssl, Config &cfg, Session &session) {
  const std::string &cmd = msg.command;
  if (cmd == "PING") {
    sendIRC(ssl, "PONG :" + (msg.params.empty() ? std::string() : msg.params[0]));
  } else if ((cmd == "376" || cmd == "422") && !session.joined) {
    // End of the MOTD, or no MOTD: the server is ready, the channels are joined with or without a password
    session.joined = true;
    if (!session.nickServ.empty()) {
      sendIRC(ssl, "PRIVMSG NickServ :IDENTIFY " + session.nickServ);
    }
    for (const auto &chan : cfg.channels) {
      sendIRC(ssl, "JOIN " + chan);
    }
  } else if (cmd == "433" && !session.joined) {
    // Nickname in use while registering
    cfg.nick += "_";
    sendIRC(ssl, "NICK " + cfg.nick);
    showNotice("*** Nickname in use, trying " + cfg.nick);
  } else if (cmd == "353") {
    collectNames(msg);
  } else if (cmd == "366") {
    finishNames(msg);
  } else if (cmd == "PRIVMSG" && msg.params.size() >= 2) {
    const std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    const std::string target = cleanText(msg.params[0]);
    std::string text = msg.params[1];
    const bool isPM = iequals(target, cfg.nick); // sent to our nick, not to a channel
    bool action = false;
    if (!text.empty() && text[0] == '\x01') {
      // CTCP: show /me actions, ignore the other requests
      const std::string actionPrefix = std::string(1, '\x01') + "ACTION ";
      if (text.compare(0, actionPrefix.size(), actionPrefix) != 0) { return; }
      text = text.substr(actionPrefix.size());
      action = true;
    }
    text = cleanText(text);
    const std::string label = isPM ? paint(MAGENTA, "PM") : colouredChannel(target);
    const bool highlight = !isPM && mentions(text, cfg.nick);
    showChat(label, nick, text, false, highlight, action);
    // The log gets plain text, without colour codes
    logToFile(cfg.logFile, "[" + (isPM ? std::string("PM") : target) + "] " + (action ? "* " + nick : "<" + nick + ">") + " " + text);
  } else if (cmd == "NOTICE" && msg.params.size() >= 2) {
    const std::string from = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    const std::string text = cleanText(msg.params[1]);
    showNotice("-" + from + "- " + text);
    logToFile(cfg.logFile, "[NOTICE] -" + from + "- " + text);
    if (!session.greeted && !session.nickServ.empty() && iequals(from, "NickServ") && text.find("You are now identified") != std::string::npos) {
      session.greeted = true;
      sendIRC(ssl, "PRIVMSG " + cfg.activeChannel + " :Hello from a secure, verified TLS IRC client!");
    }
  } else if (cmd.size() == 3 && (cmd[0] == '4' || cmd[0] == '5') && std::isdigit(static_cast<unsigned char>(cmd[1])) && std::isdigit(static_cast<unsigned char>(cmd[2]))) {
    // Error replies, for example "no such nick" or "cannot join channel"
    std::string text;
    for (size_t i = 1; i < msg.params.size(); i++) { text += (text.empty() ? "" : " ") + msg.params[i]; }
    text = cleanText(text);
    showNotice("*** " + text);
    logToFile(cfg.logFile, "[" + cmd + "] " + text);
  } else {
    logToFile(cfg.logFile, "[RAW] " + msg.command);
  }
}

void sendIRC(SSL *ssl, std::string cmd) {
  if (!ssl) return;
  // A line break inside the text would start a second command
  std::replace(cmd.begin(), cmd.end(), '\r', ' ');
  std::replace(cmd.begin(), cmd.end(), '\n', ' ');
  cmd += "\r\n";
  if (SSL_write(ssl, cmd.c_str(), static_cast<int>(cmd.size())) <= 0) {
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

// OpenSSL 3 renamed the function, LibreSSL still uses the old name
X509 *peerCertificate(SSL *ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return SSL_get1_peer_certificate(ssl);
#else
  return SSL_get_peer_certificate(ssl);
#endif
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
  if (!(iss >> token)) { return msg; }
  // IRCv3 message tags ("@time=...;id=... ") are skipped
  if (token[0] == '@') {
    if (!(iss >> token)) { return msg; }
  }
  if (token[0] == ':') {
    msg.prefix = token.substr(1);
    if (!(iss >> token)) { return msg; }
  }
  msg.command = token;
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
  std::tm local{};
  localtime_r(&now, &local);
  char buf[128] = {'\0'};
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
  return std::string(buf);
}

void logToFile(const std::string &filename, const std::string &line) {
  std::ofstream out(filename, std::ios::app);
  if (out) out << "[" << timestamp() << "] " << line << "\n";
}

// ---- Text helpers ----

std::string trimSpaces(const std::string &s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) { return ""; }
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool iequals(const std::string &a, const std::string &b) {
  return lower(a) == lower(b);
}

bool isChannelName(const std::string &name) {
  return !name.empty() && std::strchr("#&+!", name[0]) != nullptr;
}

bool hasChannel(const Config &cfg, const std::string &name) {
  for (const auto &c : cfg.channels) {
    if (iequals(c, name)) { return true; }
  }
  return false;
}

std::string cleanText(const std::string &text) {
  auto isDigit = [&text](size_t k) { return k < text.size() && std::isdigit(static_cast<unsigned char>(text[k])); };
  std::string out;
  for (size_t i = 0; i < text.size(); i++) {
    unsigned char c = static_cast<unsigned char>(text[i]);
    if (c == 0x03) { // mIRC colour: ^C, then up to 2 digits, optionally a comma and up to 2 digits
      size_t k = i + 1;
      if (isDigit(k)) {
        k++;
        if (isDigit(k)) { k++; }
        if (k < text.size() && text[k] == ',' && isDigit(k + 1)) {
          k += 2;
          if (isDigit(k)) { k++; }
        }
      }
      i = k - 1;
      continue;
    }
    if (c == '\t') { out += ' '; continue; }
    if (c < 0x20 || c == 0x7f) { continue; } // includes ESC, bold, underline and CTCP markers
    out += text[i];
  }
  return out;
}

bool mentions(const std::string &text, const std::string &nick) {
  if (nick.empty()) { return false; }
  auto isNickChar = [](char c) { return c != '\0' && (std::isalnum(static_cast<unsigned char>(c)) || std::strchr("[]\\`_^{|}-", c) != nullptr); };
  const std::string t = lower(text);
  const std::string n = lower(nick);
  // The whole nick must be there: "al" is not mentioned by "also"
  for (size_t pos = t.find(n); pos != std::string::npos; pos = t.find(n, pos + 1)) {
    bool startOk = (pos == 0) || !isNickChar(t[pos - 1]);
    bool endOk = (pos + n.size() >= t.size()) || !isNickChar(t[pos + n.size()]);
    if (startOk && endOk) { return true; }
  }
  return false;
}

// ---- Colours ----

std::string paint(const char *code, const std::string &text) {
  if (!global_cfg || !global_cfg->colour) { return text; }
  return std::string(code) + text + RESETCOLOUR;
}

// The same nick always gets the same colour (case-insensitive, like IRC nicks)
std::string nickColour(const std::string &nick) {
  static const char *palette[] = {
    "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;35m", "\033[1;36m",
    "\033[1;91m", "\033[1;92m", "\033[1;93m", "\033[1;94m", "\033[1;95m", "\033[1;96m"
  };
  unsigned int hash = 5381U;
  for (unsigned char c : nick) { hash = hash * 33U + static_cast<unsigned int>(std::tolower(c)); }
  return palette[hash % (sizeof(palette) / sizeof(palette[0]))];
}

// The same channel always gets the same colour (256-colour codes)
std::string channelColour(const std::string &channel) {
  static const int palette[] = { 39, 45, 75, 111, 141, 147, 173, 179, 180, 208, 214, 215 };
  unsigned int hash = 5381U;
  for (unsigned char c : channel) { hash = hash * 33U + static_cast<unsigned int>(std::tolower(c)); }
  return "\033[38;5;" + std::to_string(palette[hash % (sizeof(palette) / sizeof(palette[0]))]) + "m";
}

// A channel name in its colour, in bold if it is the active one
std::string colouredChannel(const std::string &channel) {
  const std::string clean = cleanText(channel);
  if (!global_cfg || !global_cfg->colour) { return clean; }
  std::string bold = iequals(clean, global_cfg->activeChannel) ? "\033[1m" : "";
  return bold + channelColour(clean) + clean + RESETCOLOUR;
}

// ---- Output ----

// Print a line above the prompt without breaking what the user is typing.
// inCallback is true inside inputHandler(), where readline redraws the prompt by itself
void printAbovePrompt(const std::string &line, bool inCallback) {
  std::lock_guard<std::mutex> lock(coutMutex);
  if (inCallback || !readlineActive) {
    std::cout << line << "\n" << std::flush;
    return;
  }
  int savedPoint = rl_point;
  char *savedLine = rl_copy_text(0, rl_end);
  rl_save_prompt();
  rl_replace_line("", 0);
  rl_redisplay();
  std::cout << "\r\033[K" << line << "\n" << std::flush;
  rl_restore_prompt();
  rl_replace_line(savedLine, 0);
  rl_point = savedPoint;
  rl_redisplay();
  free(savedLine);
}

// One chat line: [time] [label] <nick> text. The label is a channel, "PM" or "PM -> nick"
void showChat(const std::string &label, const std::string &nick, const std::string &text, bool inCallback, bool highlight, bool action) {
  std::string shownNick = paint(nickColour(nick).c_str(), nick);
  std::string who = action ? "* " + shownNick : "<" + shownNick + ">";
  std::string shownText = highlight ? paint(BOLD_YELLOW, text) : text;
  printAbovePrompt("[" + timestamp() + "] [" + label + "] " + who + " " + shownText, inCallback);
}

// Server notices and errors, in grey
void showNotice(const std::string &text, bool inCallback) {
  printAbovePrompt("[" + timestamp() + "] " + paint(GREY, text), inCallback);
}