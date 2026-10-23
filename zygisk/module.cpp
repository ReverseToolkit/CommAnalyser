// Zygisk module for CommAnalyser. CommZygisk loads `zygisk_module_entry`.
// preAppSpecialize still runs as zygote, so connectCompanion can reach the
// root companion. postAppSpecialize runs as the app and dlopens libagent.so
// from a file descriptor kept open across specialize.

#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <android/log.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>

#include "api.hpp"

namespace {

constexpr const char *kGate = "ca-gate";

void log_line(const char *message) {
    __android_log_print(ANDROID_LOG_INFO, "ca-zygisk", "%s", message);
}

int connect_abstract(const char *name) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    size_t len = strlen(name);
    if (len + 1 >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    memcpy(addr.sun_path + 1, name, len);
    socklen_t addrlen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + len);
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), addrlen) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

bool write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

std::string read_line(int fd, int timeout_ms) {
    std::string out;
    char buf[256];
    while (out.size() < 1024 && out.find('\n') == std::string::npos) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) break;
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, buf + n);
    }
    return out;
}

bool json_load(const std::string &reply, std::string *socket_name) {
    auto key = reply.find("\"load\":true");
    if (key == std::string::npos) key = reply.find("\"load\": true");
    if (key == std::string::npos) return false;
    auto sock = reply.find("\"socket\":\"");
    if (sock == std::string::npos) return false;
    sock += strlen("\"socket\":\"");
    auto end = reply.find('"', sock);
    if (end == std::string::npos) return false;
    *socket_name = reply.substr(sock, end - sock);
    return !socket_name->empty();
}

class Analyser : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        log_line("onLoad");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        log_line("pre");
        if (api_ == nullptr || env_ == nullptr || args == nullptr || args->nice_name == nullptr) {
            log_line("pre missing name");
            return;
        }
        const char *name = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (name == nullptr) return;
        log_line(name);
        ask_gate(name);
        env_->ReleaseStringUTFChars(args->nice_name, name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override { load_agent(); }

private:
    void ask_gate(const char *package) {
        int companion = api_->connectCompanion();
        log_line(companion < 0 ? "companion failed" : "companion ok");
        if (companion < 0) return;
        std::string line = std::string("{\"package\":\"") + package +
                           "\",\"pid\":" + std::to_string(getpid()) + "}\n";
        bool wrote = write_all(companion, line.data(), line.size());
        std::string reply = wrote ? read_line(companion, 1000) : std::string();
        close(companion);
        log_line(reply.c_str());
        if (!json_load(reply, &socket_)) return;

        int dir = api_->getModuleDir();
        if (dir < 0) {
            socket_.clear();
            return;
        }
        agent_fd_ = openat(dir, "libagent.so", O_RDONLY | O_CLOEXEC);
        close(dir);
        if (agent_fd_ < 0) {
            socket_.clear();
            return;
        }
        // Zygote closes every fd it does not know about during specialize.
        if (!api_->exemptFd(agent_fd_)) {
            close(agent_fd_);
            agent_fd_ = -1;
            socket_.clear();
        }
    }

    void load_agent() {
        if (agent_fd_ < 0 || socket_.empty()) return;
        android_dlextinfo info{};
        info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        info.library_fd = agent_fd_;
        void *handle = android_dlopen_ext("libagent.so", RTLD_NOW, &info);
        close(agent_fd_);
        agent_fd_ = -1;
        if (handle == nullptr) {
            socket_.clear();
            return;
        }
        using MainFn = int (*)(const char *);
        auto entry = reinterpret_cast<MainFn>(dlsym(handle, "agent_main_wait"));
        if (entry == nullptr) {
            socket_.clear();
            return;
        }
        entry(socket_.c_str());
        socket_.clear();
    }

    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    int agent_fd_ = -1;
    std::string socket_;
};

}  // namespace

static void companion_main(int client) {
    log_line("companion entry");
    std::string line = read_line(client, 1000);
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    int gate = connect_abstract(kGate);
    const char *deny = "{\"load\":false}\n";
    if (gate < 0 || !write_all(gate, line.data(), line.size())) {
        write_all(client, deny, strlen(deny));
        if (gate >= 0) close(gate);
        close(client);
        return;
    }
    std::string reply = read_line(gate, 1000);
    close(gate);
    if (reply.empty()) reply = deny;
    if (reply.back() != '\n') reply.push_back('\n');
    write_all(client, reply.data(), reply.size());
    close(client);
}

REGISTER_ZYGISK_MODULE(Analyser)
REGISTER_ZYGISK_COMPANION(companion_main)
