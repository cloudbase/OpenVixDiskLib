#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static FILE *out;
static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static int log_fd = -1;

static void init_out(void) {
    if (out) {
        return;
    }
    const char *path = getenv("SSLHOOK_LOG");
    if (!path) {
        path = "/tmp/sslhook-open.log";
    }
    out = fopen(path, "w");
    if (!out) {
        out = stderr;
    }
    log_fd = fileno(out);
    setvbuf(out, NULL, _IONBF, 0);
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

static void dump(const char *tag, const void *id, int fd, const void *buf, int num) {
    init_out();
    pthread_mutex_lock(&log_mu);
    fprintf(out, "\n==== %s %p fd=%d port=%d %d ====\n",
            tag, id, fd, fd >= 0 ? peer_port(fd) : -1, num);
    const unsigned char *p = buf;
    for (int i = 0; i < num; i++) {
        fprintf(out, "%02x", p[i]);
    }
    fprintf(out, "\n");
    pthread_mutex_unlock(&log_mu);
}

typedef int (*ssl_write_fn)(void *, const void *, int);
typedef int (*ssl_read_fn)(void *, void *, int);
typedef int (*ssl_get_fd_fn)(const void *);
typedef int (*ssl_write_ex_fn)(void *, const void *, size_t, size_t *);
typedef int (*ssl_read_ex_fn)(void *, void *, size_t, size_t *);

static ssl_get_fd_fn real_ssl_get_fd(void) {
    static ssl_get_fd_fn fn;
    if (!fn) {
        fn = (ssl_get_fd_fn)dlsym(RTLD_NEXT, "SSL_get_fd");
    }
    return fn;
}

int SSL_write(void *ssl, const void *buf, int num) {
    static ssl_write_fn real;
    if (!real) {
        real = (ssl_write_fn)dlsym(RTLD_NEXT, "SSL_write");
    }
    int fd = real_ssl_get_fd() ? real_ssl_get_fd()(ssl) : -1;
    dump("SSL_W", ssl, fd, buf, num);
    return real(ssl, buf, num);
}

int SSL_read(void *ssl, void *buf, int num) {
    static ssl_read_fn real;
    if (!real) {
        real = (ssl_read_fn)dlsym(RTLD_NEXT, "SSL_read");
    }
    int n = real(ssl, buf, num);
    if (n > 0) {
        int fd = real_ssl_get_fd() ? real_ssl_get_fd()(ssl) : -1;
        dump("SSL_R", ssl, fd, buf, n);
    }
    return n;
}

int SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    static ssl_write_ex_fn real;
    if (!real) {
        real = (ssl_write_ex_fn)dlsym(RTLD_NEXT, "SSL_write_ex");
    }
    int fd = real_ssl_get_fd() ? real_ssl_get_fd()(ssl) : -1;
    dump("SSL_WEX", ssl, fd, buf, (int)num);
    return real(ssl, buf, num, written);
}

int SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    static ssl_read_ex_fn real;
    if (!real) {
        real = (ssl_read_ex_fn)dlsym(RTLD_NEXT, "SSL_read_ex");
    }
    int rc = real(ssl, buf, num, readbytes);
    if (rc && readbytes && *readbytes > 0) {
        int fd = real_ssl_get_fd() ? real_ssl_get_fd()(ssl) : -1;
        dump("SSL_REX", ssl, fd, buf, (int)*readbytes);
    }
    return rc;
}

static int interesting_fd(int fd) {
    if (fd < 0 || fd == log_fd) {
        return 0;
    }
    int port = peer_port(fd);
    return port == 902 || port == 9020;
}

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real)(int, const void *, size_t);
    if (!real) {
        real = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    }
    if (interesting_fd(fd) && count > 0 && buf) {
        dump("WRITE", NULL, fd, buf, (int)count);
    }
    return real(fd, buf, count);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    static ssize_t (*real)(int, const void *, size_t, int);
    if (!real) {
        real = (ssize_t (*)(int, const void *, size_t, int))dlsym(RTLD_NEXT, "send");
    }
    if (interesting_fd(fd) && len > 0 && buf) {
        dump("SEND", NULL, fd, buf, (int)len);
    }
    return real(fd, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real)(int, void *, size_t);
    if (!real) {
        real = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    }
    ssize_t n = real(fd, buf, count);
    if (n > 0 && interesting_fd(fd)) {
        dump("READ", NULL, fd, buf, (int)n);
    }
    return n;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    static ssize_t (*real)(int, void *, size_t, int);
    if (!real) {
        real = (ssize_t (*)(int, void *, size_t, int))dlsym(RTLD_NEXT, "recv");
    }
    ssize_t n = real(fd, buf, len, flags);
    if (n > 0 && interesting_fd(fd)) {
        dump("RECV", NULL, fd, buf, (int)n);
    }
    return n;
}
