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

struct Session {
  std::string nickServ;
  bool joined = false;
  bool greeted = false;
  bool nickChanged = false;   // only try one alternate nick on 433
};

struct Socket {
  int fd;
  explicit Socket(int f) : fd(f) {}
  ~Socket() { if (fd >= 0) { close(fd); } }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr    = std::unique_ptr<SSL, decltype(&SSL_free)>;
using X509Ptr   = std::unique_ptr<X509, decltype(&X509_free)>;

std::atomic<bool> running(true);
std::mutex coutMutex;

SSL *global_ssl = nullptr;
Config *global_cfg = nullptr;
std::map<std::string, std::vector<std::string>> channelNicks;
std::map<std::string, std::vector<std::string>> pendingNicks;
bool readlineActive = false;
bool showRaw = false;

// ---- Declarations ----
std::string timestamp();
void logToFile(const std::string &filename, const std::string &line);
IRCMessage parseIRCMessage(const std::string &raw);
int connectToServer(const std::string &server, int port);
SSL_CTX *initSSL();
X509 *peerCertificate(SSL *ssl);
void sendIRC(SSL *ssl, std::string cmd);
bool readFromServer(SSL *ssl, std::string &inbuf);
void processInput(std::string &inbuf, SSL *ssl, Config &cfg, Session &session);
void handleMessage(const IRCMessage &msg, SSL *ssl, Config &cfg, Session &session);
bool runConnection(Config &cfg, const std::string &nickServ);
bool loadConfig(Config &cfg);
void handleSigint(int);
void inputHandler(char *input);

std::string trimSpaces(const std::string &s);
std::string lower(std::string s);
bool iequals(const std::string &a, const std::string &b);
bool isChannelName(const std::string &name);
bool hasChannel(const Config &cfg, const std::string &name);
std::string cleanText(const std::string &text);
bool mentions(const std::string &text, const std::string &nick);

std::string paint(const char *code, const std::string &text);
std::string nickColour(const std::string &nick);
std::string channelColour(const std::string &channel);
std::string colouredChannel(const std::string &channel);

void printAbovePrompt(const std::string &line, bool inCallback = false);
void showChat(const std::string &label, const std::string &nick, const std::string &text,
              bool inCallback, bool highlight, bool action = false);
void showNotice(const std::string &text, bool inCallback = false);

void collectNames(const IRCMessage &msg);
void finishNames(const IRCMessage &msg);
void addNickToChannel(const std::string &chan, const std::string &nick);
void removeNickFromChannel(const std::string &chan, const std::string &nick);
void renameNick(const std::string &oldNick, const std::string &newNick);

char *nicknameGenerator(const char *text, int state);
char **nicknameCompletion(const char *text, int start, int end);

// ---- main ----
int main() {
  signal(SIGINT, handleSigint);
  signal(SIGPIPE, SIG_IGN);  // dead sockets must not kill us

  Config cfg;
  loadConfig(cfg);
  const char *noColour = std::getenv("NO_COLOR");
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
      failures++;
      unsigned int delay = std::min(5U << std::min(failures - 1U, 4U), 60U);
      std::cerr << "[" << timestamp() << "] Retry in " << delay << " seconds...\n";
      sleep(delay);
    }
  }
  std::cout << "\n[" << timestamp() << "] *** Exiting...\n";
  return EXIT_SUCCESS;
}

// ---- Connection ----
bool runConnection(Config &cfg, const std::string &nickServ) {
  Socket sock(connectToServer(cfg.server, cfg.port));
  if (sock.fd < 0) { return false; }
  SslCtxPtr ctx(initSSL(), SSL_CTX_free);
  if (!ctx) { return false; }
  SslPtr ssl(SSL_new(ctx.get()), SSL_free);
  if (!ssl) { ERR_print_errors_fp(stderr); return false; }

  SSL_set_fd(ssl.get(), sock.fd);
  SSL_set_tlsext_host_name(ssl.get(), cfg.server.c_str());
  if (SSL_set1_host(ssl.get(), cfg.server.c_str()) != 1) {
    std::cerr << "Error: could not set the host name to verify." << std::endl;
    return false;
  }
  if (SSL_connect(ssl.get()) <= 0) { ERR_print_errors_fp(stderr); return false; }

  X509Ptr cert(peerCertificate(ssl.get()), X509_free);
  if (!cert) { std::cerr << "Error: No certificate presented by server." << std::endl; return false; }
  if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
    std::cerr << "Error: certificate verification failed." << std::endl;
    return false;
  }

  std::cout << "SSL connection established and certificate verified." << std::endl;
  std::cout << "[" << timestamp() << "] Connected to " << cfg.server
            << " with " << SSL_get_cipher(ssl.get()) << " encryption.\n";

  global_ssl = ssl.get();
  channelNicks.clear();
  pendingNicks.clear();

  sendIRC(ssl.get(), "NICK " + cfg.nick);
  sendIRC(ssl.get(), "USER " + cfg.user + " 0 * :" + cfg.realname);

  // Readline setup + history
  rl_attempted_completion_function = nicknameCompletion;
  const char *home = std::getenv("HOME");
  std::string histPath = (home ? std::string(home) : std::string(".")) + "/.0veric_history";
  read_history(histPath.c_str());
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
    struct timeval tv{1, 0};
    int activity = select(std::max(sslFd, STDIN_FILENO) + 1, &readfds, nullptr, nullptr, &tv);
    if (activity < 0) {
      if (errno == EINTR) { continue; }
      perror("select");
      break;
    }
    if (activity == 0) { continue; }  // timeout, nothing ready

    if (FD_ISSET(sslFd, &readfds)) {
      if (!readFromServer(ssl.get(), inbuf)) {
        printAbovePrompt("[" + timestamp() + "] Connection closed by server.");
        break;
      }
      processInput(inbuf, ssl.get(), cfg, session);
    }
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      rl_callback_read_char();
    }
  }

  readlineActive = false;
  rl_callback_handler_remove();
  write_history(histPath.c_str());
  SSL_shutdown(ssl.get());
  global_ssl = nullptr;
  return true;
}

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
  } while (SSL_pending(ssl) > 0);
  return true;
}

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
  if (inbuf.size() > 65536) { inbuf.clear(); }
}

// ---- NAMES handling ----
void collectNames(const IRCMessage &msg) {
  if (msg.params.size() < 4) { return; }
  std::vector<std::string> &list = pendingNicks[lower(msg.params[2])];
  std::istringstream names(msg.params[3]);
  std::string nick;
  while (names >> nick) {
    size_t first = nick.find_first_not_of("~&@%+");
    if (first == std::string::npos) { continue; }
    nick = nick.substr(first);
    nick = nick.substr(0, nick.find('!'));
    if (!nick.empty()) { list.push_back(nick); }
  }
}

void finishNames(const IRCMessage &msg) {
  if (msg.params.size() < 2) { return; }
  auto it = pendingNicks.find(lower(msg.params[1]));
  if (it == pendingNicks.end()) { return; }
  channelNicks[it->first] = std::move(it->second);
  pendingNicks.erase(it);
}

void addNickToChannel(const std::string &chan, const std::string &nick) {
  if (nick.empty() || chan.empty()) { return; }
  auto &list = channelNicks[lower(chan)];
  for (const auto &n : list) {
    if (iequals(n, nick)) { return; }
  }
  list.push_back(nick);
}

void removeNickFromChannel(const std::string &chan, const std::string &nick) {
  auto it = channelNicks.find(lower(chan));
  if (it == channelNicks.end()) { return; }
  auto &v = it->second;
  v.erase(std::remove_if(v.begin(), v.end(),
                         [&](const std::string &n) { return iequals(n, nick); }),
          v.end());
}

void renameNick(const std::string &oldNick, const std::string &newNick) {
  for (auto &kv : channelNicks) {
    for (auto &n : kv.second) {
      if (iequals(n, oldNick)) { n = newNick; }
    }
  }
}

// ---- Readline completion ----
char *nicknameGenerator(const char *text, int state) {
  static size_t list_index;
  static size_t len;
  static std::vector<std::string> matches;

  if (!state) {
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

char **nicknameCompletion(const char *text, int start, int end) {
  (void)start; (void)end;
  rl_attempted_completion_over = 1;
  return rl_completion_matches(text, nicknameGenerator);
}

// ---- Input ----
void inputHandler(char *input) {
  if (!input) { running = false; return; }
  std::string cmd(input);
  free(input);
  if (cmd.empty()) { return; }
  add_history(cmd.c_str());

  auto isCmd = [&](const char *c) { return cmd == c; };
  auto isPrefix = [&](const char *p) { return cmd.rfind(p, 0) == 0; };

  if (isCmd("/quit") || isCmd("/exit")) {
    sendIRC(global_ssl, "QUIT :Bye!");
    running = false;
  } else if (isCmd("/list")) {
    std::string text = "Joined to the following channel(s)";
    for (const auto &channel : global_cfg->channels) {
      text += "\n" + colouredChannel(channel);
    }
    printAbovePrompt(text, true);
  } else if (isCmd("/names")) {
    if (!global_cfg->activeChannel.empty()) {
      sendIRC(global_ssl, "NAMES " + global_cfg->activeChannel);
    }
  } else if (isCmd("/clear")) {
    std::cout << "\033[2J\033[H" << std::flush;
  } else if (isCmd("/debug")) {
    showRaw = !showRaw;
    printAbovePrompt(std::string("*** Raw server lines ") + (showRaw ? "ON" : "OFF"), true);
  } else if (isPrefix("/raw ")) {
    sendIRC(global_ssl, cmd.substr(5));
  } else if (isPrefix("/join ")) {
    std::string chan = trimSpaces(cmd.substr(6));
    if (!isChannelName(chan)) {
      printAbovePrompt("*** Usage: /join #channel", true);
      return;
    }
    sendIRC(global_ssl, "JOIN " + chan);
    if (!hasChannel(*global_cfg, chan)) { global_cfg->channels.push_back(chan); }
    global_cfg->activeChannel = chan;
  } else if (isPrefix("/part")) {
    std::string chan = trimSpaces(cmd.substr(5));
    if (chan.empty()) { chan = global_cfg->activeChannel; }
    if (!isChannelName(chan)) {
      printAbovePrompt("*** Usage: /part [#channel]", true);
      return;
    }
    sendIRC(global_ssl, "PART " + chan + " :Leaving");
    auto &v = global_cfg->channels;
    v.erase(std::remove_if(v.begin(), v.end(),
                           [&](const std::string &c) { return iequals(c, chan); }),
            v.end());
    if (iequals(global_cfg->activeChannel, chan)) {
      global_cfg->activeChannel = v.empty() ? std::string() : v.front();
    }
  } else if (isPrefix("/close")) {
    // same as /part of active channel
    if (!global_cfg->activeChannel.empty()) {
      std::string chan = global_cfg->activeChannel;
      sendIRC(global_ssl, "PART " + chan + " :Leaving");
      auto &v = global_cfg->channels;
      v.erase(std::remove_if(v.begin(), v.end(),
                             [&](const std::string &c) { return iequals(c, chan); }),
              v.end());
      global_cfg->activeChannel = v.empty() ? std::string() : v.front();
    }
  } else if (isPrefix("/switch ")) {
    std::string chan = trimSpaces(cmd.substr(8));
    for (auto &c : global_cfg->channels) {
      if (iequals(c, chan)) {
        global_cfg->activeChannel = c;
        printAbovePrompt("[" + timestamp() + "] *** Switched to " + colouredChannel(c), true);
        return;
      }
    }
    printAbovePrompt("[" + timestamp() + "] *** Not in channel " + cleanText(chan), true);
  } else if (isPrefix("/msg ")) {
    std::istringstream iss(cmd.substr(5));
    std::string target;
    iss >> target;
    std::string text;
    std::getline(iss, text);
    if (!text.empty() && text[0] == ' ') { text.erase(0, 1); }
    if (target.empty() || text.empty()) {
      printAbovePrompt("*** Usage: /msg target message", true);
      return;
    }
    sendIRC(global_ssl, "PRIVMSG " + target + " :" + text);
    std::string label = isChannelName(target) ? colouredChannel(target)
                                              : paint(MAGENTA, "PM -> " + cleanText(target));
    showChat(label, global_cfg->nick, cleanText(text), true, false);
  } else if (isPrefix("/me ")) {
    std::string text = cmd.substr(4);
    if (text.empty() || global_cfg->activeChannel.empty()) { return; }
    sendIRC(global_ssl, "PRIVMSG " + global_cfg->activeChannel + " :\x01ACTION " + text + "\x01");
    showChat(colouredChannel(global_cfg->activeChannel), global_cfg->nick,
             cleanText(text), true, false, true);
  } else if (isPrefix("/nick ")) {
    std::string newNick = trimSpaces(cmd.substr(6));
    if (newNick.empty()) {
      printAbovePrompt("*** Usage: /nick newnick", true);
      return;
    }
    sendIRC(global_ssl, "NICK " + newNick);
  } else if (isCmd("/away")) {
    sendIRC(global_ssl, "AWAY :Away");
  } else if (isCmd("/back")) {
    sendIRC(global_ssl, "AWAY");
  } else if (isPrefix("/topic ")) {
    if (global_cfg->activeChannel.empty()) { return; }
    sendIRC(global_ssl, "TOPIC " + global_cfg->activeChannel + " :" + cmd.substr(7));
  } else if (isPrefix("/whois ")) {
    sendIRC(global_ssl, "WHOIS " + cmd.substr(7));
  } else {
    if (global_cfg->activeChannel.empty()) {
      printAbovePrompt("*** No active channel, use /join #channel", true);
      return;
    }
    sendIRC(global_ssl, "PRIVMSG " + global_cfg->activeChannel + " :" + cmd);
    showChat(colouredChannel(global_cfg->activeChannel), global_cfg->nick,
             cleanText(cmd), true, false);
  }
}

void handleSigint(int) { running = false; }

// ---- Config ----
bool loadConfig(Config &cfg) {
  const char *home = std::getenv("HOME");
  std::ifstream file((home ? std::string(home) + "/" : std::string("./")) + ".0veric.conf");
  if (!file) { return false; }
  bool channelsGiven = false;
  std::string line;
  while (std::getline(file, line)) {
    line = trimSpaces(line);
    if (line.empty() || line[0] == '#') { continue; }
    size_t split = line.find_first_of(" \t");
    if (split == std::string::npos) { continue; }
    std::string key = line.substr(0, split);
    std::string value = trimSpaces(line.substr(split));
    if (value.empty()) { continue; }
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
      if (!channelsGiven) { cfg.channels.clear(); channelsGiven = true; }
      if (!hasChannel(cfg, value)) { cfg.channels.push_back(value); }
    }
    else if (key == "logfile") cfg.logFile = value;
    else if (key == "colour") cfg.colour = (value != "off" && value != "no" && value != "0");
  }
  cfg.activeChannel = cfg.channels.empty() ? std::string() : cfg.channels.front();
  return true;
}

// ---- Message handling ----
void handleMessage(const IRCMessage &msg, SSL *ssl, Config &cfg, Session &session) {
  const std::string &cmd = msg.command;

  if (cmd == "PING") {
    sendIRC(ssl, "PONG :" + (msg.params.empty() ? std::string() : msg.params[0]));
  } else if ((cmd == "376" || cmd == "422") && !session.joined) {
    session.joined = true;
    if (!session.nickServ.empty()) {
      sendIRC(ssl, "PRIVMSG NickServ :IDENTIFY " + session.nickServ);
    }
    for (const auto &chan : cfg.channels) {
      sendIRC(ssl, "JOIN " + chan);
    }
  } else if (cmd == "433" && !session.joined && !session.nickChanged) {
    session.nickChanged = true;
    cfg.nick += "_";
    sendIRC(ssl, "NICK " + cfg.nick);
    showNotice("*** Nickname in use, trying " + cfg.nick);
  } else if (cmd == "001") {
    // Welcome: nothing to do here, join happens on 376/422
  } else if (cmd == "353") {
    collectNames(msg);
  } else if (cmd == "366") {
    finishNames(msg);
  } else if (cmd == "JOIN" && !msg.prefix.empty() && !msg.params.empty()) {
    std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    std::string chan = cleanText(msg.params[0]);
    if (iequals(nick, cfg.nick)) {
      addNickToChannel(chan, nick);
    } else {
      addNickToChannel(chan, nick);
    }
  } else if (cmd == "PART" && !msg.prefix.empty() && !msg.params.empty()) {
    std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    std::string chan = cleanText(msg.params[0]);
    removeNickFromChannel(chan, nick);
  } else if (cmd == "QUIT" && !msg.prefix.empty()) {
    std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    for (auto &kv : channelNicks) { removeNickFromChannel(kv.first, nick); }
  } else if (cmd == "KICK" && msg.params.size() >= 2) {
    std::string chan = cleanText(msg.params[0]);
    std::string who  = cleanText(msg.params[1]);
    removeNickFromChannel(chan, who);
  } else if (cmd == "NICK" && !msg.prefix.empty() && !msg.params.empty()) {
    std::string oldNick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    std::string newNick = cleanText(msg.params[0]);
    renameNick(oldNick, newNick);
    if (iequals(oldNick, cfg.nick)) { cfg.nick = newNick; }
  } else if (cmd == "PRIVMSG" && msg.params.size() >= 2) {
    const std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    const std::string target = cleanText(msg.params[0]);
  } else if (cmd == "PRIVMSG" && msg.params.size() >= 2) {
    const std::string nick = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    const std::string target = cleanText(msg.params[0]);
    std::string text = msg.params[1];
    const bool isPM = iequals(target, cfg.nick);
    bool action = false;

    if (!text.empty() && text[0] == '\x01') {
      // CTCP: handle ACTION, reply to VERSION/PING, ignore everything else
      const std::string body = text.substr(1, text.size() >= 2 && text.back() == '\x01'
                                                 ? text.size() - 2
                                                 : std::string::npos);
      if (body.rfind("ACTION ", 0) == 0) {
        text = body.substr(7);
        action = true;
      } else if (body == "VERSION") {
        sendIRC(ssl, "NOTICE " + nick + " :\x01VERSION 0veric :3\x01");
        return;
      } else if (body.rfind("PING", 0) == 0) {
        sendIRC(ssl, "NOTICE " + nick + " :\x01" + body + "\x01");
        return;
      } else {
        return; // other CTCP requests are ignored
      }
    }

    text = cleanText(text);
    const std::string label = isPM ? paint(MAGENTA, "PM") : colouredChannel(target);
    const bool highlight = !isPM && mentions(text, cfg.nick);
    showChat(label, nick, text, false, highlight, action);
    logToFile(cfg.logFile, "[" + (isPM ? std::string("PM") : target) + "] " +
                           (action ? "* " + nick : "<" + nick + ">") + " " + text);

  } else if (cmd == "NOTICE" && msg.params.size() >= 2) {
    const std::string from = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    std::string text = msg.params[1];
    // Ignore CTCP replies (VERSION, PING) we might receive from other clients
    if (!text.empty() && text[0] == '\x01') { return; }
    text = cleanText(text);
    showNotice("-" + from + "- " + text);
    logToFile(cfg.logFile, "[NOTICE] -" + from + "- " + text);
    if (!session.greeted && !session.nickServ.empty() &&
        iequals(from, "NickServ") &&
        text.find("You are now identified") != std::string::npos) {
      session.greeted = true;
      if (!cfg.activeChannel.empty()) {
        sendIRC(ssl, "PRIVMSG " + cfg.activeChannel +
                     " :Hello from a secure, verified TLS IRC client!");
      }
    }

  } else if (cmd == "TOPIC" && msg.params.size() >= 2) {
    const std::string chan = cleanText(msg.params[0]);
    const std::string topic = cleanText(msg.params[1]);
    const std::string who = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    showNotice("*** " + who + " set topic on " + cleanText(chan) + ": " + topic);
    logToFile(cfg.logFile, "[TOPIC] " + chan + " by " + who + ": " + topic);

  } else if (cmd == "KICK" && msg.params.size() >= 3) {
    const std::string chan = cleanText(msg.params[0]);
    const std::string who  = cleanText(msg.params[1]);
    const std::string reason = cleanText(msg.params[2]);
    const std::string by = cleanText(msg.prefix.substr(0, msg.prefix.find('!')));
    showNotice("*** " + who + " was kicked from " + cleanText(chan) +
               " by " + by + " (" + reason + ")");
    logToFile(cfg.logFile, "[KICK] " + who + " from " + chan + " by " + by + ": " + reason);

  } else if (cmd == "NICK" && !msg.prefix.empty() && !msg.params.empty()) {
    // (already handled above; kept here for clarity if the earlier branch is removed)

  } else if (cmd.size() == 3 && (cmd[0] == '4' || cmd[0] == '5') &&
             std::isdigit(static_cast<unsigned char>(cmd[1])) &&
             std::isdigit(static_cast<unsigned char>(cmd[2]))) {
    // Error replies, e.g. "no such nick" or "cannot join channel"
    std::string text;
    for (size_t i = 1; i < msg.params.size(); i++) {
      text += (text.empty() ? "" : " ") + msg.params[i];
    }
    text = cleanText(text);
    showNotice("*** " + text);
    logToFile(cfg.logFile, "[" + cmd + "] " + text);

  } else {
    logToFile(cfg.logFile, "[RAW] " + msg.command);
  }
}

// ---- Network ----
void sendIRC(SSL *ssl, std::string cmd) {
  if (!ssl) { return; }
  std::replace(cmd.begin(), cmd.end(), '\r', ' ');
  std::replace(cmd.begin(), cmd.end(), '\n', ' ');
  cmd += "\r\n";
  if (SSL_write(ssl, cmd.c_str(), static_cast<int>(cmd.size())) <= 0) {
    ERR_print_errors_fp(stderr);
  }
}

SSL_CTX *initSSL() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) { ERR_print_errors_fp(stderr); return nullptr; }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_default_verify_paths(ctx);
  return ctx;
}

X509 *peerCertificate(SSL *ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return SSL_get1_peer_certificate(ssl);
#else
  return SSL_get_peer_certificate(ssl);
#endif
}

// Modern, IPv6-capable replacement for gethostbyname()
int connectToServer(const std::string &server, int port) {
  struct addrinfo hints{};
  hints.ai_family   = AF_UNSPEC;     // allow IPv4 and IPv6
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string portStr = std::to_string(port);
  struct addrinfo *res = nullptr;
  int rc = getaddrinfo(server.c_str(), portStr.c_str(), &hints, &res);
  if (rc != 0) {
    std::cerr << "No such host: " << server
              << " (" << gai_strerror(rc) << ")" << std::endl;
    return -1;
  }

  int sockfd = -1;
  for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0) { continue; }
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) { break; }
    close(sockfd);
    sockfd = -1;
  }
  freeaddrinfo(res);

  if (sockfd < 0) { perror("Connection failed"); }
  return sockfd;
}

// ---- Parsing ----
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

// ---- Utilities ----
std::string timestamp() {
  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_r(&now, &local);
  char buf[128] = {'\0'};
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
  return std::string(buf);
}

void logToFile(const std::string &filename, const std::string &line) {
  std::ofstream out(filename, std::ios::app);
  if (out) { out << "[" << timestamp() << "] " << line << "\n"; }
}

// ---- Text helpers ----
std::string trimSpaces(const std::string &s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) { return ""; }
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
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
  auto isDigit = [&text](size_t k) {
    return k < text.size() && std::isdigit(static_cast<unsigned char>(text[k]));
  };
  std::string out;
  for (size_t i = 0; i < text.size(); i++) {
    unsigned char c = static_cast<unsigned char>(text[i]);
    if (c == 0x03) { // mIRC colour: ^C + up to 2 digits, optionally ",N"
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
    if (c < 0x20 || c == 0x7f) { continue; } // ESC, bold, underline, CTCP markers
    out += text[i];
  }
  return out;
}

bool mentions(const std::string &text, const std::string &nick) {
  if (nick.empty()) { return false; }
  auto isNickChar = [](char c) {
    return c != '\0' &&
           (std::isalnum(static_cast<unsigned char>(c)) ||
            std::strchr("[]\\`_^{|}-", c) != nullptr);
  };
  const std::string t = lower(text);
  const std::string n = lower(nick);
  for (size_t pos = t.find(n); pos != std::string::npos; pos = t.find(n, pos + 1)) {
    bool startOk = (pos == 0) || !isNickChar(t[pos - 1]);
    bool endOk   = (pos + n.size() >= t.size()) || !isNickChar(t[pos + n.size()]);
    if (startOk && endOk) { return true; }
  }
  return false;
}

// ---- Colours ----
std::string paint(const char *code, const std::string &text) {
  if (!global_cfg || !global_cfg->colour) { return text; }
  return std::string(code) + text + RESETCOLOUR;
}

std::string nickColour(const std::string &nick) {
  static const char *palette[] = {
    "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;35m", "\033[1;36m",
    "\033[1;91m", "\033[1;92m", "\033[1;93m", "\033[1;94m", "\033[1;95m", "\033[1;96m"
  };
  unsigned int hash = 5381U;
  for (unsigned char c : nick) { hash = hash * 33U + static_cast<unsigned int>(std::tolower(c)); }
  return palette[hash % (sizeof(palette) / sizeof(palette[0]))];
}

std::string channelColour(const std::string &channel) {
  static const int palette[] = { 39, 45, 75, 111, 141, 147, 173, 179, 180, 208, 214, 215 };
  unsigned int hash = 5381U;
  for (unsigned char c : channel) { hash = hash * 33U + static_cast<unsigned int>(std::tolower(c)); }
  return "\033[38;5;" + std::to_string(palette[hash % (sizeof(palette) / sizeof(palette[0]))]) + "m";
}

std::string colouredChannel(const std::string &channel) {
  const std::string clean = cleanText(channel);
  if (!global_cfg || !global_cfg->colour) { return clean; }
  std::string bold = iequals(clean, global_cfg->activeChannel) ? "\033[1m" : "";
  return bold + channelColour(clean) + clean + RESETCOLOUR;
}

// ---- Output ----
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

void showChat(const std::string &label, const std::string &nick, const std::string &text,
              bool inCallback, bool highlight, bool action) {
  const std::string nickCode = nickColour(nick);
  std::string shownNick = paint(nickCode.c_str(), nick);
  std::string who = action ? "* " + shownNick : "<" + shownNick + ">";
  std::string shownText = highlight ? paint(BOLD_YELLOW, text) : text;
  printAbovePrompt("[" + timestamp() + "] [" + label + "] " + who + " " + shownText, inCallback);
}

void showNotice(const std::string &text, bool inCallback) {
  printAbovePrompt("[" + timestamp() + "] " + paint(GREY, text), inCallback);
}