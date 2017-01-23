/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "IptablesRestoreController.h"

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/file.h>

#include "Controllers.h"

constexpr char IPTABLES_RESTORE_PATH[] = "/system/bin/iptables-restore";
constexpr char IP6TABLES_RESTORE_PATH[] = "/system/bin/ip6tables-restore";

constexpr char PING[] = "#PING\n";

constexpr size_t PING_SIZE = sizeof(PING) - 1;

// TODO: This mirrors &gCtls.iptablesRestoreCtrl in production and is duplicated
// here to aid testing. It allows us to unit-test IptablesRestoreController without
// needing to construct a fully fledged Controllers object.
/* static */ IptablesRestoreController* sInstance = nullptr;

class IptablesProcess {
public:
    IptablesProcess(pid_t pid, int stdIn, int stdOut, int stdErr) :
        pid(pid),
        stdIn(stdIn),
        processTerminated(false) {

        pollFds[STDOUT_IDX] = { .fd = stdOut, .events = POLLIN };
        pollFds[STDERR_IDX] = { .fd = stdErr, .events = POLLIN };
    }

    ~IptablesProcess() {
        close(stdIn);
        close(pollFds[STDOUT_IDX].fd);
        close(pollFds[STDERR_IDX].fd);
    }

    const pid_t pid;
    const int stdIn;

    struct pollfd pollFds[2];
    std::string errBuf;

    bool processTerminated;

    static constexpr size_t STDOUT_IDX = 0;
    static constexpr size_t STDERR_IDX = 1;
};

IptablesRestoreController::IptablesRestoreController() :
    mIpRestore(nullptr),
    mIp6Restore(nullptr) {
}

IptablesRestoreController::~IptablesRestoreController() {
}

/* static */
IptablesProcess* IptablesRestoreController::forkAndExec(const IptablesProcessType type) {
    const char* const cmd = (type == IPTABLES_PROCESS) ?
        IPTABLES_RESTORE_PATH : IP6TABLES_RESTORE_PATH;

    // Create the pipes we'll use for communication with the child
    // process. One each for the child's in, out and err files.
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];

    if (pipe2(stdin_pipe, 0) == -1 ||
        pipe2(stdout_pipe, 0) == -1 ||
        pipe2(stderr_pipe, 0) == -1) {

        PLOG(ERROR) << "pipe2() failed";
        return nullptr;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // The child process. Reads from stdin, writes to stderr and stdout.

        // stdin_pipe[1] : The write end of the stdin pipe.
        // stdout_pipe[0] : The read end of the stdout pipe.
        // stderr_pipe[0] : The read end of the stderr pipe.
        if (close(stdin_pipe[1]) == -1 ||
            close(stdout_pipe[0]) == -1 ||
            close(stderr_pipe[0]) == -1) {

            PLOG(WARNING) << "close() failed";
        }

        // stdin_pipe[0] : The read end of the stdin pipe.
        // stdout_pipe[1] : The write end of the stdout pipe.
        // stderr_pipe[1] : The write end of the stderr pipe.
        if (dup2(stdin_pipe[0], 0) == -1 ||
            dup2(stdout_pipe[1], 1) == -1 ||
            dup2(stderr_pipe[1], 2) == -1) {
            PLOG(ERROR) << "dup2() failed";
            abort();
        }

        if (execl(cmd,
                  cmd,
                  "--noflush",  // Don't flush the whole table.
                  "-w",         // Wait instead of failing if the lock is held.
                  "-v",         // Verbose mode, to make sure our ping is echoed
                                // back to us.
                  nullptr) == -1) {
            PLOG(ERROR) << "execl(" << cmd << ", ...) failed";
            abort();
        }

        // This statement is unreachable. We abort() upon error, and execl
        // if everything goes well.
        return nullptr;
    }

    // The parent process. Writes to stdout and stderr and reads from stdin.
    if (child_pid == -1) {
        PLOG(ERROR) << "fork() failed";
        return nullptr;
    }

    // stdin_pipe[0] : The read end of the stdin pipe.
    // stdout_pipe[1] : The write end of the stdout pipe.
    // stderr_pipe[1] : The write end of the stderr pipe.
    if (close(stdin_pipe[0]) == -1 ||
        close(stdout_pipe[1]) == -1 ||
        close(stderr_pipe[1]) == -1) {
        PLOG(WARNING) << "close() failed";
    }

    return new IptablesProcess(child_pid, stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);
}

void sigchldHandler(int /* signal_number */, siginfo_t *siginfo, void* /* context */) {
    // Save and restore errno to prevent threads from spuriously seeing
    // incorrect errors due to errors from this signal handler.
    int saved_errno = errno;

    // Notify the IptablesRestoreController so that it can try to recover. Log
    // relevant information if it's one of the process we care about. netd
    // forks other processes as well, so there's no need to spam the logs
    // every time one of those dies.
    const pid_t child_pid = siginfo->si_pid;
    const IptablesRestoreController::IptablesProcessType process =
            sInstance->notifyChildTermination(child_pid);

    if (process != IptablesRestoreController::INVALID_PROCESS) {
        // This should return immediately because we've been informed that
        // |child_pid| just exited.
        pid_t wait_result = waitpid(child_pid, nullptr, WNOHANG);
        if (wait_result < 0) {
            PLOG(WARNING) << "waitpid for child " << child_pid << " unexpectedly failed";
        }

        if (siginfo->si_code == CLD_EXITED) {
            LOG(WARNING) << "iptables[6]-restore process exited (pid=" << child_pid
                         << ") exit_status=" << siginfo->si_status
                         << " type=" << process;
        } else {
            LOG(WARNING) << "iptables[6]-restore process was signalled (pid=" << child_pid
                         << ") signal=" << siginfo->si_status
                         << " type=" << process;
        }
    }

    errno = saved_errno;
}

/* static */
void IptablesRestoreController::installSignalHandler(IptablesRestoreController *singleton) {
    if (singleton == nullptr) {
        LOG(ERROR) << "installSignalHandler: singleton == nullptr";
    }

    sInstance = singleton;

    struct sigaction sa = {};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigchldHandler;
    const int err = sigaction(SIGCHLD, &sa, nullptr);
    if (err < 0) {
        PLOG(ERROR) << "Unable to set SIGCHLD handler.";
    }
}

IptablesRestoreController::IptablesProcessType
IptablesRestoreController::notifyChildTermination(pid_t pid) {
    // We minimize the amount of work that we do from the signal handler, given
    // that this can be called at any arbitrary point of time.

    if (mIpRestore != nullptr && mIpRestore->pid == pid) {
        mIpRestore->processTerminated = true;
        return IPTABLES_PROCESS;
    }

    if (mIp6Restore != nullptr && mIp6Restore->pid == pid) {
        mIp6Restore->processTerminated = true;
        return IP6TABLES_PROCESS;
    }

    return INVALID_PROCESS;
}

// TODO: Return -errno on failure instead of -1.
// TODO: Maybe we should keep a rotating buffer of the last N commands
// so that they can be dumped on dumpsys.
int IptablesRestoreController::sendCommand(const IptablesProcessType type,
                                           const std::string& command) {
   std::unique_ptr<IptablesProcess> *process =
           (type == IPTABLES_PROCESS) ? &mIpRestore : &mIp6Restore;

    // We might need to fork a new process if we haven't forked one yet, or
    // if the forked process terminated.
    //
    // NOTE: For a given command, this is the last point at which we try to
    // recover from a child death. If the child dies at some later point during
    // the execution of this method, we will receive an EPIPE and return an
    // error. The command will then need to be retried at a higher level.
    if (process->get() == nullptr || (*process)->processTerminated) {
        // Fork a new iptables[6]-restore process.
        IptablesProcess *newProcess = IptablesRestoreController::forkAndExec(type);
        if (newProcess == nullptr) {
            LOG(ERROR) << "Unable to fork ip[6]tables-restore, type: " << type;
            return -1;
        }

        process->reset(newProcess);
    }

    // TODO: Investigate why this horrible hackery is necessary. We're currently
    // sending iptables[6]-restore malformed commands. They appear to contain garbage
    // after the last "\n". They obviously "work" because we fork a new process
    // for every command so it doesn't matter whether the process chokes after
    // the last successful COMMIT.
    const std::string fixedCommand = fixCommandString(command);

    if (!android::base::WriteFully((*process)->stdIn,
                                   fixedCommand.data(),
                                   fixedCommand.length())) {
        PLOG(ERROR) << "Unable to send command";
    }

    if (!android::base::WriteFully((*process)->stdIn, PING, PING_SIZE)) {
        PLOG(ERROR) << "Unable to send ping command : " << type;
        return -1;
    }

    if (!drainAndWaitForAck(*process)) {
        LOG(ERROR) << "Timed out waiting for response from iptables process: " << (*process)->pid;
        return -1;
    }

    return 0;
}

/* static */
std::string IptablesRestoreController::fixCommandString(const std::string& command) {
    std::string commandDup = command;
    commandDup.erase(commandDup.find_last_of("\n") + 1);
    return commandDup;
}

void IptablesRestoreController::maybeLogStderr(const std::unique_ptr<IptablesProcess> &process,
                                               const char* buf, ssize_t numBytes) {
    ssize_t lastNewline = 0;
    for (ssize_t i = 0; i < numBytes; ++i) {
        if (buf[i] == '\n') {
            process->errBuf.append(buf + lastNewline, (i - lastNewline));
            LOG(ERROR) << "Iptables : " << process->errBuf;
            process->errBuf.clear();
            lastNewline = i;
        }
    }

    // Append all remaining characters to the buffer so that they're logged the
    // next time 'round.
    if (lastNewline < (static_cast<ssize_t>(numBytes) - 1)) {
        process->errBuf.append(buf + lastNewline,
                               static_cast<ssize_t>(numBytes) - 1 - lastNewline);
    }
}

// The maximum number of times we poll(2) for a response on our set of polled
// fds. Chosen so that the overall timeout is 1s.
static constexpr int MAX_RETRIES = 10;

// The timeout (in millis) for each call to poll. The maximum wait is
// |POLL_TIMEOUT_MS * MAX_RETRIES|. Chosen so that the overall timeout is 1s.
static constexpr int POLL_TIMEOUT_MS = 100;

/* static */
bool IptablesRestoreController::drainAndWaitForAck(
        const std::unique_ptr<IptablesProcess> &process) {
    bool receivedAck = false;
    int timeout = 0;
    std::string out;
    while (!receivedAck && (timeout++ < MAX_RETRIES)) {
        int numEvents = TEMP_FAILURE_RETRY(
            poll(process->pollFds, ARRAY_SIZE(process->pollFds), POLL_TIMEOUT_MS));
        if (numEvents == -1) {
            PLOG(ERROR) << "Poll failed.";
            return false;
        }

        // We've timed out, which means something has gone wrong - we know that stdout should have
        // become available to read with the ACK message.
        if (numEvents == 0) {
            continue;
        }

        char buffer[256];
        for (size_t i = 0; i < ARRAY_SIZE(process->pollFds); ++i) {
            const struct pollfd &pollfd = process->pollFds[i];
            if (pollfd.revents & POLLIN) {
                // TODO: We read a maximum of 256 bytes for each call to poll.
                // We should change this so that we can read as much input as we
                // can from the descriptor without blocking.
                const ssize_t size = TEMP_FAILURE_RETRY(read(pollfd.fd, buffer, sizeof(buffer)));

                // This should never happen. Poll just told us that we have
                // something available.
                if (size == -1) {
                    PLOG(ERROR) << "Unable to read from descriptor";
                    return false;
                }

                if (i == IptablesProcess::STDOUT_IDX) {
                    // i == STDOUT_IDX : look for the ping response. We use
                    // a string buffer here because it's possible (but unlikely)
                    // that only a subsection of the PING response is available
                    // on the pipe when poll returns for the first time. We use
                    // find instead of operator== to be robust in the case of
                    // additional stdout logging.
                    out.append(buffer, size);
                    if (out.find(PING) != std::string::npos) {
                        receivedAck = true;
                    }
                } else {
                    // i == STDERR_IDX implies stderr, log.
                    IptablesRestoreController::maybeLogStderr(process, buffer, size);
                }
            }
        }
    }

    return receivedAck;
}

int IptablesRestoreController::execute(const IptablesTarget target, const std::string& command) {
    std::lock_guard<std::mutex> lock(mLock);

    int res = 0;
    if (target == V4 || target == V4V6) {
        res |= sendCommand(IPTABLES_PROCESS, command);
    }
    if (target == V6 || target == V4V6) {
        res |= sendCommand(IP6TABLES_PROCESS, command);
    }
    return res;
}
