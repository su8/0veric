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

<<<<<<< HEAD
It's stored in **~/.0veric.conf**

```python
server irc.libera.chat
port 6697
nick Lunnis
user Lunnis 0 * :GNU IRC Client
channel #debian
logfile /home/user/.0veric.log
```
=======
By defualt I've chosen to `press Enter` to fetch data from the channels that you've joined.
>>>>>>> 7d8c8803ba8890e49b0171cc816d7bb816d6557f
