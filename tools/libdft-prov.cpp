/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "syscall_hook.h"

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
using namespace std;

// Pin full path
KNOB< std::string > KnobPinFullPath(KNOB_MODE_WRITEONCE, "pintool", "pin_path", "/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux/", "pin full path");
// Tool full path
KNOB< std::string > KnobToolsFullPath(KNOB_MODE_WRITEONCE, "pintool", "tools_path", "/home/chuqiz/GitHub/libdft64/tools/obj-intel64/", "grand parent tool full path");

static KNOB<std::string> KnobOutputDir(KNOB_MODE_WRITEONCE, "pintool", "o", "/tmp/libdft-prov_logs", "specify output directory");
// Child configuration
// // Application name
// KNOB< std::string > KnobChildApplicationName(KNOB_MODE_WRITEONCE, "pintool", "child_app_name", "win_child_process",
//                                         "child application name");
// PinTool name
KNOB< std::string > KnobChildToolName(KNOB_MODE_WRITEONCE, "pintool", "child_tool_name", "libdft.so",
                                 "child tool full path");

/*
 * DummyTool (i.e, libdft)
 *
 * used for demonstrating libdft
 */

//
// MMAP
//

static MMAPFILE mmap_open(const char *path) {
	int fd = open(path, O_RDWR|O_CREAT, 0644);
	if(fd == -1) perror_exit("mmap_open open");
	return fd;
}
static inline void mmap_close(MMAPFILE fd) {
	close(fd);
}
static void *mmap_map(MMAPFILE fd, size_t size, size_t offset = 0) {
	USIZE thesize=0;
	OS_FileSizeFD(fd,&thesize);
	if(static_cast<size_t>(thesize) < offset+size)
		ftruncate(fd, offset+size);

	void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if(ret == MAP_FAILED) perror_exit("mmap_map mmap");

	return ret;
}
static inline void mmap_unmap(void *buf, size_t size) {
	if(buf) munmap(buf, size);
}

//
// 
//
#define atomic_postinc32(x) __sync_fetch_and_add((x), 1)

#define ALLOC_GRAN (8192) // Linux and OS X are fine with >= 1 page.
#define ALLOC_GRAN_MASK (~(ALLOC_GRAN-1))

#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000
#define IS_SYSCALL  0x08000000
#define SIZE_MASK   0xFF

struct logstate {
	uint32_t change_count;
	uint32_t changelist_number;
	uint32_t is_filtered;
	uint32_t first_changelist_number;
	uint32_t parent_id;
	uint32_t this_pid;
};

struct change {
	uint64_t address;
	uint64_t data;
	uint32_t changelist_number;
	uint32_t flags;
};

////////////////////////////////////////////////////////////////
// PIN globals
////////////////////////////////////////////////////////////////

static TLS_KEY thread_state_tls_key;
static REG writeea_scratch_reg;
static const ADDRINT WRITEEA_SENTINEL = (sizeof(ADDRINT) > 4) ? (ADDRINT)0xDEADDEADDEADDEADull : (ADDRINT)0xDEADDEADul;
// ^ Don't worry, programs are free to collide with this. It's really just for debug assertions.

// TODO: Something that supports multiple filter ranges, etc.
static ADDRINT filter_ip_low = 0;
static ADDRINT filter_ip_high = (ADDRINT)-1;

//
// STATES
//

class Thread_State {
	uint32_t qira_fileid;

	FILE *strace_file;

	MMAPFILE file_handle;
	void *logstate_region;
	void *mapped_region;
	size_t mapped_region_start;
	size_t mapped_region_end;

public:
	static inline Thread_State *get(THREADID tid) {
		return static_cast<Thread_State*>(PIN_GetThreadData(thread_state_tls_key, tid));
	}
	static inline Thread_State *get() {
		return get(PIN_ThreadId());
	}
	
	Thread_State(uint32_t fileid, uint32_t parent, uint32_t chglist) : qira_fileid(fileid) {
		char path[2100];
		int len = snprintf(path, sizeof path, "%s/%u", KnobOutputDir.Value().c_str(), qira_fileid);
		file_handle = mmap_open(path);
		
		mapped_region_start = 0;
		mapped_region_end = ALLOC_GRAN; // Initial size
		mapped_region = mmap_map(file_handle, mapped_region_end - mapped_region_start, mapped_region_start);
		logstate_region = mmap_map(file_handle, sizeof(struct logstate), 0);
		
		snprintf(path+len, sizeof(path) - len, "_strace");
		strace_file = fopen(path, "wb");
		if(!strace_file) perror_exit("fopen");
		
		struct logstate *log = logstate();
		log->change_count = 1;
		log->changelist_number = chglist;
		log->is_filtered = 1;
		log->first_changelist_number = chglist;
		log->parent_id = parent;
		log->this_pid = qira_fileid;
	}

	~Thread_State() {
		mmap_unmap(logstate_region, sizeof(struct logstate));
		mmap_unmap(mapped_region, mapped_region_end - mapped_region_start);
		mmap_close(file_handle);
		fclose(strace_file);
	}

	static inline void tls_destruct(void *tls) { delete static_cast<Thread_State *>(tls); }

	inline struct logstate *logstate() const {
		return static_cast<struct logstate *>(logstate_region);
	}

	// Get a change, shifting (and expanding) the loaded region of the file as necessary
	inline struct change *change(size_t i) {
		size_t target = sizeof(struct change) * (i+1); // +1 because first "change" is actually a header.
		register size_t endtarget = target + sizeof(struct change);
		if(endtarget > mapped_region_end) { // Ran out of space, shift the mapped_region frame forward.
			size_t region_size = mapped_region_end - mapped_region_start;
			mmap_unmap(mapped_region, region_size);

			const register size_t behind = 32*sizeof(struct change); // Overlap the old region a bit. Seems prudent.
			mapped_region_start = target > behind ? target - behind : 0;
			mapped_region_start &= ALLOC_GRAN_MASK;
			region_size = region_size*3/2 + 2*ALLOC_GRAN; // Allocate more space than we did last time.
			region_size &= ALLOC_GRAN_MASK;

			// Clip to maximum 512 MB.
			if(region_size > (512<<20)) region_size = (512<<20);
			if(endtarget > mapped_region_start+region_size) { // Bizarre edge case that won't happen.
				region_size = (endtarget - mapped_region_start + ALLOC_GRAN) & ALLOC_GRAN_MASK;
			}
			mapped_region_end = mapped_region_start + region_size;
			mapped_region = mmap_map(file_handle, region_size, mapped_region_start);
		}
		return reinterpret_cast<struct change *>((char*)mapped_region + target - mapped_region_start);
	}

	// TODO: Maybe need to do something smart to not screw up on forks
	inline int strace_printf(const char *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		int ret = vfprintf(strace_file, fmt, args);
		va_end(args);
		return ret;
	}

	inline void strace_flush() {
		fflush(strace_file);
	}
};

class Process_State {
	PIN_LOCK lock;
	uint32_t main_id; // lol
	volatile uint32_t threads_created;
	volatile uint32_t changelist_number;
	FILE *base_file;

public:
	string *image_folder;

	Process_State() : main_id(0xDEADBEEF), threads_created(0xDEADBEEF), changelist_number(1), base_file(NULL), image_folder(NULL) {
		PIN_InitLock(&lock);
	}

	void init(INT pid) {
		// Called at program start, and also after a fork to update self for a new child.
		// Thread start will be called after this.
		main_id = 0x7FFFFFFF & (pid << 16); // New tracefile format needs to separate out the program from the first thread.
		threads_created = 0;
		
		char path[2100];
		int len = snprintf(path, sizeof path, "%s/%u", KnobOutputDir.Value().c_str(), main_id);
		
		// if(KnobMakeStandaloneTrace) {
		// 	if(image_folder) delete image_folder;
		// 	image_folder = new string(path);
		// 	image_folder->append("_images");
		// 	mkdir(image_folder->c_str(), 0755);
		// }
		
		snprintf(path+len, sizeof(path) - len, "_base");
		FILE *new_base_file = fopen(path, "wb+");
		if(!new_base_file) perror_exit("fopen");
		if(base_file) {
			long x = ftell(base_file);
			rewind(base_file);
			while(x > 0) {
				// Use `path` as a copy buffer, why not.
				size_t y = fread(path, 1, sizeof path, base_file);
				size_t z = fwrite(path, 1, y, new_base_file);
				ASSERT(y > 0 && z == y, "File IO error while copying base file.");
				x -= y;
			}
			fclose(base_file);
		}
		base_file = new_base_file;
	}

	void fini() {
		fclose(base_file);
	}

#ifndef TARGET_WINDOWS
	void fork_before(THREADID tid) {
		PIN_GetLock(&lock, 0);
		// sync(); // commented out to be compatible with later PIN versions. Seems to work...
		// TODO: Close all files, reopen later
		// I think this is only required for the current tid's data structure.
	}
	void fork_after_parent(THREADID tid) {
		PIN_ReleaseLock(&lock);
	}
	void fork_after_child(THREADID tid, int new_pid) {
		init(new_pid);
		changelist_number -= 1; // hax
		thread_start(tid);
		PIN_ReleaseLock(&lock);
	}
#endif

	void thread_start(THREADID tid) {
		uint32_t t = atomic_postinc32(&threads_created);
		uint32_t qira_fileid = main_id ^ t; // TODO: New trace format needs more (i.e. arbitrary) name bits
		Thread_State *state = new Thread_State(qira_fileid, main_id == qira_fileid ? -1 : main_id, claim_changelist_number());
		PIN_SetThreadData(thread_state_tls_key, static_cast<void*>(state), tid);
	}

	void thread_fini(THREADID tid) {}

	inline int claim_changelist_number() {
		return atomic_postinc32(&changelist_number);
	}

	inline int base_printf(const char *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		int ret = vfprintf(base_file, fmt, args);
		va_end(args);
		return ret;
	}

	inline void base_flush() {
		fflush(base_file);
	}
};

static Process_State process_state;
VOID ForkBefore      (THREADID tid, const CONTEXT *ctx, VOID *v) { process_state.fork_before(tid); }
VOID ForkAfterParent (THREADID tid, const CONTEXT *ctx, VOID *v) { process_state.fork_after_parent(tid); }
VOID ForkAfterChild  (THREADID tid, const CONTEXT *ctx, VOID *v) {
	syscall_tls_destruct(PIN_GetThreadData(syscall_tls_key, tid));
	PIN_SetThreadData(syscall_tls_key, NULL, tid);
	process_state.fork_after_child(tid, PIN_GetPid());
}

bool FollowChild(CHILD_PROCESS cProcess, VOID* userData) {
  fprintf(stdout, "before child:%u\n", getpid());
  // bool res;
  int appArgc;
  CHAR const* const* appArgv;
  // OS_PROCESS_ID pid = CHILD_PROCESS_GetId(cProcess);

  CHILD_PROCESS_GetCommandLine(cProcess, &appArgc, &appArgv);

  // Set Pin's command line for child process
  int pinArgc = 0;
  const int pinArgcMax = 6;
  char const* pinArgv[pinArgcMax];

  std::string pin = KnobPinFullPath.Value() + "pin";
  fprintf(stdout, "argv 0: %s\n", pin.c_str());
  pinArgv[pinArgc++] = pin.c_str();
  pinArgv[pinArgc++] = "-follow_execv";
  pinArgv[pinArgc++] = "-t";
  std::string tool = KnobToolsFullPath.Value() + KnobChildToolName.Value();
  fprintf(stdout, "argv -follow-execv -t : %s\n", tool.c_str());
  pinArgv[pinArgc++] = tool.c_str();
  pinArgv[pinArgc++] = "--";

  CHILD_PROCESS_SetPinCommandLine(cProcess, pinArgc, pinArgv);
  return true;
}

int main(int argc, char **argv) {
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize Pin; optimized branch */
  if (unlikely(PIN_Init(argc, argv)))
    /* Pin initialization failed */
    goto err;

  /* initialize the core tagging engine */
  if (unlikely(libdft_init() != 0))
    /* failed */
    goto err;

  hook_file_syscall();
  // Register a notification handler that is called when the application
  // forks a new process.
  PIN_AddForkFunction(FPOINT_BEFORE, ForkBefore, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, ForkAfterParent, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkAfterChild, 0);
  /* TODO(): add child hook */
  PIN_AddFollowChildProcessFunction(FollowChild, 0);
  /* start Pin */
  PIN_StartProgram();
  /* typically not reached; make the compiler happy */
  return EXIT_SUCCESS;

err: /* error handling */
  /* return */
  return EXIT_FAILURE;
}
