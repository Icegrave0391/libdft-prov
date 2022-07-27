#include "syscall_hook.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "fdmap.h"
#include "tagmap.h"
#include "taintmap.h"

#include <iostream>
#include <map>
#include <set>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <arpa/inet.h>
#include <unistd.h>

#define FUZZING_INPUT_FILE "cur_input"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
extern std::map <int, std::string> fdmap;
extern TAINT_MAP taint_map;

std::set<int> fuzzing_fd_set;

// /* socket related syscalls */
static int sock_syscalls[] = {
	__NR_connect,
  __NR_bind
};

std::map <int, std::string> create_audit_syscall_map() {
  std::map<int, std::string> m;
  m[__NR_read] = "read";
  m[__NR_pread64] = "pread64";
  m[__NR_recvfrom] = "recvfrom";
  m[__NR_write] = "write";
  m[__NR_writev] = "writev";
  return m;
}
std::map <int, std::string> audit_syscalls = create_audit_syscall_map();

// static std::map<int, std::string> audit_syscalls = {
//   {__NR_read, "read"},
//   {__NR_pread64, "pread64"},
//   {__NR_write, "write"},
//   {__NR_writev, "writev"},
//   {__NR_socket, "socket"},
//   {__NR_recvfrom, "recvfrom"},
//   {__NR_recvmsg, "recvmsg"},
//   {__NR_recvmmsg, "recvmmsg"}
// };

// static unsigned int stdin_read_off = 0;

static unsigned int syscall_audit_seq_id = 0;
static bool tainted = false;

inline bool is_tainted() { return tainted; }

static inline bool is_fuzzing_fd(int fd) {
  return fd == STDIN_FILENO || fuzzing_fd_set.count(fd) > 0;
}

static inline void add_fuzzing_fd(int fd) {
  if (fd > 0)
    fuzzing_fd_set.insert(fd);
}

static inline void remove_fuzzing_fd(int fd) { fuzzing_fd_set.erase(fd); }

static inline bool should_track_fd(int fd) {
  // return fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO;
  return true;
}

//
enum {
  SYSCALL_AUDIT_IN,
  SYSCALL_AUDIT_OUT,
};

static inline void handle_syscall_taint(THREADID tid, syscall_ctx_t *ctx) {
  // TODO() just padding here
  // TODO() to be implemented
  switch (ctx->nr) {
    /* audit-input syscalls: set taint sources */
    case __NR_read:
    case __NR_pread64:
    case __NR_recvfrom:
    {
      const int fd = ctx->arg[SYSCALL_ARG0];
      const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
      size_t count = ctx->arg[SYSCALL_ARG2];
      size_t ret = ctx->ret;
      if (unlikely((int)ret == -1))
        return;
      
      if (should_track_fd(fd)) {
        tainted = true;
        // std::string sysname = audit_syscalls.at(ctx->nr);
        auto it = audit_syscalls.find(ctx->nr);
        if (it == audit_syscalls.end()) {
          return;
        }
        std::string sysname = it->second;

        LOGD("[%s] fd: %d, addr: %p, size: %lu / %lu pid: %d\n", sysname.c_str(),
             fd, (char *)buf, ret, count, getpid());
        tag_t t = tag_alloc<tag_t>(syscall_audit_seq_id);    
        tagmap_setn(buf, count, t);
        LOGD("[%s][set taint] %s\n", sysname.c_str(), tag_sprint(t).c_str());
        // update taintmap
        std::string source = lookup_fdmap(fdmap, fd);
        update_taintmap(taint_map, t, source);
      } else {
        tagmap_clrn(buf, ret);
      }
      syscall_audit_seq_id += 1;
      break;
    }
    case __NR_write:
    case __NR_writev: /* ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */
    { 
      const int fd = ctx->arg[SYSCALL_ARG0];
      size_t ret = ctx->ret;
      if (unlikely((int)ret == -1 || !should_track_fd(fd)))
        return;

      tag_t t;

      if (ctx->nr == __NR_write) {
        /* write() */
        const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
        const size_t count = ctx->arg[SYSCALL_ARG2];
        LOGD("[write] fd: %d, addr: %p, size: %lu / %lu pid: %d\n", fd, (char *)buf, ret, count, getpid());
        t = tagmap_getn(buf, ret);
        LOGD("[write][get taint] %s\n", tag_sprint(t).c_str());
      } else {
        /* writev() */
        const struct iovec *iov_array = (struct iovec *)ctx->arg[SYSCALL_ARG1];
        const struct iovec *iov;
        size_t iov_tot;
        const int iovcnt = ctx->arg[SYSCALL_ARG2];
        
        tag_t ts = tag_traits<tag_t>::cleared_val;
        for (int i = 0; i < iovcnt; i++) {
          iov = &iov_array[i];
          iov_tot = (ret > (size_t)iov->iov_len) ? (size_t)iov->iov_len : ret;
          tag_t tmp_t = tagmap_getn((ADDRINT)iov->iov_base, iov_tot);
          ts = tag_combine(ts, tmp_t);
        }
        t = ts; 
        LOGD("[writev] fd: %d, addr: %p, size: %lu, pid: %d\n", fd, (char *)iov_array, ret, getpid());
        LOGD("[writev][get taint] %s\n", tag_sprint(t).c_str());
      }

      syscall_audit_seq_id += 1;

      std::string target = lookup_fdmap(fdmap, fd);
      std::set<std::string> taint_set = lookup_taintmap(taint_map, t);
      // LOGU("[TAINT] %s <= %s\n", target.c_str(), set_to_string(taint_set).c_str());
      break;
    }
    default:
      break;
  }
  return;
}

/* __NR_open post syscall hook */
static void post_open_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  if (unlikely(fd < 0))
    return;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG0];
  update_fdmap(fdmap, fd, std::string(file_name));
}

/* __NR_openat post syscall hook */
// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG1];
  update_fdmap(fdmap, fd, std::string(file_name));
}

static void post_dup_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  update_fdmap(fdmap, ret, lookup_fdmap(fdmap, old_fd));
}

static void post_dup2_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  const int new_fd = ctx->arg[SYSCALL_ARG1];
  update_fdmap(fdmap, new_fd, lookup_fdmap(fdmap, old_fd));
}

/* __NR_close post syscall hook */
static void post_close_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  if (is_fuzzing_fd(fd)) {
    remove_fuzzing_fd(fd);
    LOGD("[close] fd: %d \n", fd);
  }
}

/*
 * socketcall(2) handler
 *
 * attach taint-sources in the following
 * syscalls:
 * 	socket(2), accept(2), recv(2),
 * 	recvfrom(2), recvmsg(2)
 *
 * everything else is left intact in order
 * to avoid taint-leaks
 */
static void post_socketcall_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* arguments */
  switch (ctx->nr)
  {
  case __NR_bind:
  case __NR_connect:  // ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, ...);
  {
    if (unlikely((long)ctx->ret < 0))
      return;
    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    
    int fd = ctx->arg[SYSCALL_ARG0];
    const struct sockaddr_in *addr = (struct sockaddr_in *) ctx->arg[SYSCALL_ARG1];

    // inet_pton(AF_INET, (const char *)&addr->sin_addr, ip, sizeof(ip));
    inet_ntop(AF_INET, (const char *)&addr->sin_addr, ip, sizeof(ip));
    port = htons (addr->sin_port);
    std::stringstream ss;
    ss << port;
    std::string ip_str = std::string(ip) + ":" + ss.str();

    update_fdmap(fdmap, fd, ip_str);
    break;
  }
  default:
    break;
  }
}

//
// Auditing-input SYSCALLS: read, pread64, recvfrom, recv -----------------------------------------------------------------------------
//

static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
  fprintf(stdout, "[read] fd: %ld\n", ctx->arg[SYSCALL_ARG0]);
  handle_syscall_taint(tid, ctx);
}

/* __NR_pread64 post syscall hook */
static void post_pread64_hook(THREADID tid, syscall_ctx_t *ctx) {
  LOGD("[pread] fd: %ld\n", ctx->arg[SYSCALL_ARG0]);
  handle_syscall_taint(tid, ctx);
}

/* __NR_recvfrom post syscall hook */
static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx) {
  handle_syscall_taint(tid, ctx);
}

//
// Auditing-output SYSCALLS: write, writev -----------------------------------------------------------------------------
//

/* ssize_t write(int fd, const void *buf, size_t count); */
static void post_write_hook(THREADID tid, syscall_ctx_t *ctx) {
  handle_syscall_taint(tid, ctx);
}

/* ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */
static void post_writev_hook(THREADID tid, syscall_ctx_t *ctx) {
  handle_syscall_taint(tid, ctx);
}

// void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t
// offset);
/* __NR_mmap post syscall hook */
static void post_mmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  const int fd = ctx->arg[SYSCALL_ARG4];
  const int prot = ctx->arg[SYSCALL_ARG2];
  // PROT_READ 0x1
  if ((void *)ret == (void *)-1 || !(prot & 0x1))
    return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];
  const off_t read_off = ctx->arg[SYSCALL_ARG5];
  // fprintf(stderr, "[mmap] fd: %d(%d), addr: %x, readoff: %ld, nr:%d \n", fd,
  //       is_fuzzing_fd(fd), buf, read_off, nr);
  if (is_fuzzing_fd(fd)) {
    tainted = true;
    LOGD("[mmap] fd: %d, offset: %ld, size: %lu\n", fd, read_off, nr);
    for (unsigned int i = 0; i < nr; i++) {
      tag_t t = tag_alloc<tag_t>(read_off + i);
      tagmap_setb(buf + i, t);
    }
  } else {
    tagmap_clrn(buf, nr);
  }
}

static void post_munmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  if ((void *)ret == (void *)-1)
    return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];

  // std::cerr <<"[munmap] addr: " << buf << ", nr: "<< nr << std::endl;
  tagmap_clrn(buf, nr);
}

void hook_file_syscall() {
  /* fd operation syscalls */
  (void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  (void)syscall_set_post(&syscall_desc[__NR_openat], post_openat_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup2_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup3], post_dup2_hook);
  (void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);
  /* memory operation syscalls */
  (void)syscall_set_post(&syscall_desc[__NR_mmap], post_mmap_hook);
  (void)syscall_set_post(&syscall_desc[__NR_munmap], post_munmap_hook);
  /* audit-in syscalls */
  (void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  (void)syscall_set_post(&syscall_desc[__NR_pread64], post_pread64_hook);
  (void)syscall_set_post(&syscall_desc[__NR_recvfrom], post_recvfrom_hook);
  /* audit-out syscalls */
  (void)syscall_set_post(&syscall_desc[__NR_write], post_write_hook);
  (void)syscall_set_post(&syscall_desc[__NR_writev], post_writev_hook);

  for (int sock_nr: sock_syscalls)
    (void)syscall_set_post(&syscall_desc[sock_nr], post_socketcall_hook);
}
