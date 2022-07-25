#include "syscall_hook.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "tagmap.h"

#include <iostream>
#include <set>
#include <sys/syscall.h>
#include <unistd.h>

#define FUZZING_INPUT_FILE "cur_input"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
std::set<int> fuzzing_fd_set;
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
  return fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO;
}

//
enum {
  SYSCALL_AUDIT_IN,
  SYSCALL_AUDIT_OUT,
};

static inline void handle_syscall_taint(THREADID tid, syscall_ctx_t *ctx, const tag_t &tag) {
  return;
}

/* __NR_open post syscall hook */
static void post_open_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  if (unlikely(fd < 0))
    return;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG0];
  if (strstr(file_name, FUZZING_INPUT_FILE) != NULL) {
    add_fuzzing_fd(fd);
    LOGD("[open] fd: %d : %s \n", fd, file_name);
  }
}

/* __NR_openat post syscall hook */
// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG1];
  if (strstr(file_name, FUZZING_INPUT_FILE) != NULL) {
    add_fuzzing_fd(fd);
    LOGD("[openat] fd: %d : %s \n", fd, file_name);
  }
}

static void post_dup_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  if (is_fuzzing_fd(old_fd)) {
    LOGD("[dup] fd: %d -> %d\n", old_fd, ret);
    add_fuzzing_fd(ret);
  }
}

static void post_dup2_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  const int new_fd = ctx->arg[SYSCALL_ARG1];
  if (is_fuzzing_fd(old_fd)) {
    add_fuzzing_fd(new_fd);
    LOGD("[dup2] fd: %d -> %d\n", old_fd, new_fd);
  }
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

//
// Auditing-input SYSCALLS: read, pread64, recvfrom, recv -----------------------------------------------------------------------------
//

static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* read() was not successful; optimized branch */
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;

  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  size_t count = ctx->arg[SYSCALL_ARG2];
  
  /* add taint-source */
  if (should_track_fd(fd)) {
    tainted = true;
    /* set the tag markings */
    // Attn: use count replace nr, but count may be very very large!
    if (count > nr + 32) {
      count = nr + 32;
    }
    LOGD("[read] fd: %d, addr: %p, size: %lu / %lu\n", fd,
         (char *)buf, nr, count);
    tag_t t = tag_alloc<tag_t>(syscall_audit_seq_id);    
    tagmap_setn(buf, count, t);
    LOGD("[read][set] %s\n", tag_sprint(t).c_str());
    handle_syscall_taint(tid, ctx, t);
    syscall_audit_seq_id += 1;
    /* set the taint tag of return register */
    tagmap_setb_reg(tid, DFT_REG_RAX, 0, BDD_LEN_LB);
  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, nr);
  }
}

/* __NR_pread64 post syscall hook */
static void post_pread64_hook(THREADID tid, syscall_ctx_t *ctx) {
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  size_t count = ctx->arg[SYSCALL_ARG2];

  if (should_track_fd(fd)) {
    tainted = true;
    LOGD("[pread64] fd: %d, size: %lu / %lu\n", fd, nr,
         count);
    if (count > nr + 32) {
      count = nr + 32;
    }
    /* set the tag markings */
    tag_t t = tag_alloc<tag_t>(syscall_audit_seq_id);
    tagmap_setn(buf, count, t);
    LOGD("[pread64][set] %s\n", tag_sprint(t).c_str());
    syscall_audit_seq_id += 1;
  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, count);
  }
}

/* __NR_recvfrom post syscall hook */
static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx) {
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  size_t count = ctx->arg[SYSCALL_ARG2];

  if (should_track_fd(fd)) {
    tainted = true;
    LOGD("[recvfrom] fd: %d, size: %lu / %lu\n", fd, nr,
         count);
    if (count > nr + 32) {
      count = nr + 32;
    }
    /* set the tag markings */
    tag_t t = tag_alloc<tag_t>(syscall_audit_seq_id);
    tagmap_setn(buf, count, t);
    LOGD("[recvfrom][set] %s\n", tag_sprint(t).c_str());
    syscall_audit_seq_id += 1;
  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, count);
  }
}

/* ssize_t write(int fd, const void *buf, size_t count); */
static void post_write_hook(THREADID tid, syscall_ctx_t *ctx) {
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;
  
  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  size_t count = ctx->arg[SYSCALL_ARG2];

  /* consume taint-source */
  if (should_track_fd(fd)) {
    if (count > nr + 32) {
      count = nr + 322;
    }
    /* get the taint markings */
    LOGD("[write] fd: %d, addr: %p, size: %lu / %lu\n", fd, (char *)buf, nr, count);
    tag_t t = tagmap_getn(buf, count);
    LOGD("[write][get] %s\n", tag_sprint(t).c_str());
    syscall_audit_seq_id += 1;
  }
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
}
