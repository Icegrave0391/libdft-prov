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
#include "fdmap.h"

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// Pin full path
KNOB< std::string > KnobPinFullPath(KNOB_MODE_WRITEONCE, "pintool", "pin_path", "/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux/", "pin full path");
// Tool full path
KNOB< std::string > KnobToolsFullPath(KNOB_MODE_WRITEONCE, "pintool", "tools_path", "/home/chuqiz/GitHub/libdft64/tools/obj-intel64/", "grand parent tool full path");

// Child configuration
// Application name
KNOB< std::string > KnobChildApplicationName(KNOB_MODE_WRITEONCE, "pintool", "child_app_name", "win_child_process",
                                        "child application name");
// PinTool name
KNOB< std::string > KnobChildToolName(KNOB_MODE_WRITEONCE, "pintool", "child_tool_name", "libdft.so",
                                 "child tool full path");

/*
 * DummyTool (i.e, libdft)
 *
 * used for demonstrating libdft
 */

pid_t parent_pid;
PIN_LOCK pinLock;

VOID BeforeFork(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    std::cerr << "TOOL: Before fork." << std::endl;
    PIN_ReleaseLock(&pinLock);
    parent_pid = PIN_GetPid();
}
 
VOID AfterForkInParent(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    std::cerr << "TOOL: After fork in parent." << std::endl;
    PIN_ReleaseLock(&pinLock);
 
    if (PIN_GetPid() != parent_pid)
    {
        std::cerr << "PIN_GetPid() fails in parent process" << std::endl;
        exit(-1);
    }
}
 
VOID AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    std::cerr << "TOOL: After fork in child." << std::endl;
    PIN_ReleaseLock(&pinLock);
 
    if ((PIN_GetPid() == parent_pid) || (getppid() != parent_pid))
    {
        std::cerr << "PIN_GetPid() fails in child process" << std::endl;
        exit(-1);
    }
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

void fini(INT32 code, VOID* v) {
  fprintf(stdout, "OVER!\n");
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
  PIN_AddFiniFunction(fini, 0);
  // Register a notification handler that is called when the application
  // forks a new process.
  PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
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
