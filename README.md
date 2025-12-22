# 0veric
small and simple chat client (irc)

---

# Compile

```bash
make -j8  # 8 cores/threads to use in parallel compile
sudo/doas make install
```

# Requirements

gcc/clang/llvm , libssl-dev, readline and openssl installed.

### Using configuration file

It's stored in **~/.0veric.conf**

```python
server irc.libera.chat
port 6697
nick Lunnis
user Lunnis 0 * :GNU IRC Client
channel #debian
logfile /home/user/.0veric.log
```