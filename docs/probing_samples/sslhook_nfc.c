#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static FILE *out;
static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static int log_fd = -1;
static int ready;

static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_read)(int, void *, size_t);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_readv)(int, const struct iovec *, int);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
static int (*real_ssl_write)(void *, const void *, int);
static int (*real_ssl_read)(void *, void *, int);
static int (*real_ssl_get_fd)(const void *);

__attribute__((constructor))
static void init_syms(void) {
    real_write = dlsym(RTLD_NEXT, "write");
    real_read = dlsym(RTLD_NEXT, "read");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_writev = dlsym(RTLD_NEXT, "writev");
    real_readv = dlsym(RTLD_NEXT, "readv");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    real_ssl_write = dlsym(RTLD_NEXT, "SSL_write");
    real_ssl_read = dlsym(RTLD_NEXT, "SSL_read");
    real_ssl_get_fd = dlsym(RTLD_NEXT, "SSL_get_fd");
    const char *path = getenv("SSLHOOK_LOG");
    if (!path) {
        path = "/tmp/sslhook-write.log";
    }
    out = fopen(path, "w");
    if (!out) {
        out = stderr;
    }
    log_fd = fileno(out);
    setvbuf(out, NULL, _IONBF, 0);
    ready = 1;
    fprintf(out, "hook loaded write=%p ssl_write=%p\n",
            (void *)real_write, (void *)real_ssl_write);
}

static int peer_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &len) != 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return -1;
}

static void dump(const char *tag, int fd, const void *buf, int num) {
    if (!ready || !out || fd == log_fd || num <= 0 || num > 1024 * 1024) {
        return;
    }
    int port = peer_port(fd);
    if (port <= 0 || port == 443) {
        return;
    }
    const unsigned char *p = buf;
    /* Skip TLS records. */
    if (num >= 3 && p[0] == 0x16 && p[1] == 0x03) {
        return;
    }
    if (num >= 3 && p[0] == 0x17 && p[1] == 0x03) {
        return;
    }
    pthread_mutex_lock(&log_mu);
    fprintf(out, "\n==== %s fd=%d port=%d %d ====\n", tag, fd, port, num);
    for (int i = 0; i < num; i++) {
        fprintf(out, "%02x", p[i]);
    }
    fprintf(out, "\n");
    pthread_mutex_unlock(&log_mu);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (real_write == NULL) {
        return syscall(SYS_write, fd, buf, count);
    }
    if (ready && out && fd != log_fd) {
        static int nlogged;
        if (nlogged < 40) {
            fprintf(out, "write fd=%d port=%d n=%zu\n", fd, peer_port(fd), count);
            nlogged++;
        }
    }
    dump("WRITE", fd, buf, (int)count);
    return real_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (real_read == NULL) {
        return syscall(SYS_read, fd, buf, count);
    }
    ssize_t n = real_read(fd, buf, count);
    if (n > 0) {
        dump("READ", fd, buf, (int)n);
    }
    return n;
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    if (real_send == NULL) {
        return syscall(SYS_sendto, fd, buf, len, flags, NULL, 0);
    }
    dump("SEND", fd, buf, (int)len);
    return real_send(fd, buf, len, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    if (real_recv == NULL) {
        return syscall(SYS_recvfrom, fd, buf, len, flags, NULL, 0);
    }
    ssize_t n = real_recv(fd, buf, len, flags);
    if (n > 0) {
        dump("RECV", fd, buf, (int)n);
    }
    return n;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (real_writev == NULL) {
        return syscall(SYS_writev, fd, iov, iovcnt);
    }
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }
    if (total > 0 && total <= 1024 * 1024) {
        unsigned char *buf = malloc(total);
        if (buf) {
            size_t off = 0;
            for (int i = 0; i < iovcnt; i++) {
                memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
                off += iov[i].iov_len;
            }
            dump("WRITEV", fd, buf, (int)total);
            free(buf);
        }
    }
    return real_writev(fd, iov, iovcnt);
}

int SSL_write(void *ssl, const void *buf, int num) {
    if (real_ssl_write == NULL) {
        real_ssl_write = dlsym(RTLD_NEXT, "SSL_write");
    }
    int fd = real_ssl_get_fd ? real_ssl_get_fd(ssl) : -1;
    dump("SSL_W", fd, buf, num);
    return real_ssl_write(ssl, buf, num);
}

int SSL_read(void *ssl, void *buf, int num) {
    if (real_ssl_read == NULL) {
        real_ssl_read = dlsym(RTLD_NEXT, "SSL_read");
    }
    int n = real_ssl_read(ssl, buf, num);
    if (n > 0) {
        int fd = real_ssl_get_fd ? real_ssl_get_fd(ssl) : -1;
        dump("SSL_R", fd, buf, n);
    }
    return n;
}

static void dump_msghdr(const char *tag, int fd, const struct msghdr *msg) {
    if (!msg || !msg->msg_iov) {
        return;
    }
    size_t total = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
        total += msg->msg_iov[i].iov_len;
    }
    if (total == 0 || total > 1024 * 1024) {
        return;
    }
    unsigned char *buf = malloc(total);
    if (!buf) {
        return;
    }
    size_t off = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
        memcpy(buf + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        off += msg->msg_iov[i].iov_len;
    }
    dump(tag, fd, buf, (int)total);
    free(buf);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (real_sendmsg == NULL) {
        real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    }
    if (ready && out && fd != log_fd) {
        static int nlogged;
        if (nlogged < 20) {
            fprintf(out, "sendmsg fd=%d port=%d\n", fd, peer_port(fd));
            nlogged++;
        }
    }
    dump_msghdr("SENDMSG", fd, msg);
    return real_sendmsg(fd, msg, flags);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    if (real_recvmsg == NULL) {
        real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    }
    ssize_t n = real_recvmsg(fd, msg, flags);
    if (n > 0) {
        dump_msghdr("RECVMSG", fd, msg);
    }
    return n;
}
