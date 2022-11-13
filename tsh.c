/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * Tsh avoids exiting the shell on error most of the time because the shell is
 * supposed to be a long-running process.
 *
 * The shell supports I/O redirection and doesn't support pipes. For output
 * redirection, we employ mode_t 0644 where the file's owner can read and write
 * while the group and all other users can only read.
 *
 * Tsh uses sigsuspend to avoid busy waiting.
 *
 * The shell distinguishes builtin and non-builtin commands. For non-builtin
 * commands, it forks a child process to execute the user's job.
 *
 * Each job is identified by either a process ID (PID) or a job ID (JID). The
 * latter is a positive integer denoted with the prefix "%".
 *
 * Each child process has a unique process group ID so that background children
 * won't be influenced by SIGINT or SIGTSTP and there will always be at most one
 * foreground job currently running in the shell.
 *
 * The parent process will either wait for the job to finish [foreground job] or
 * print a useful message including the job id, the process id and the command
 * line that causes this action [background job].
 *
 * Builtin commands includes quit, jobs, fg and bg.
 *
 * If the command line ends with an ampersand (&), tsh will run the job in the
 * background. Otherwise, it runs the job in the foreground.
 *
 * If there is no foreground job, SIGINT and SIGTSTP will have no effect.
 *
 * If any job terminates or stops because it receives a signal that tsh didn't
 * catch, the shell will print a message with the job's JID and PID, and the
 * offending signal number.
 *
 * Wrapper functions for system calls and other functions are included to detect
 * possible errors.
 *
 * Relevant errors of each function is included in the block comment.
 *
 * @author Zixuan Zheng <zzheng3@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Indicates whether open() has a third argument, which indicates an output
redirection */
#define MODE_ENABLED 1

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

void Open(int *fdptr, const char *pathname, int mode_enabled, sigset_t mask);
void Dup2(int oldfd, int newfd, sigset_t mask);
void Close(int fd, sigset_t mask);
void Execve(const char *filename, char *const argv[], char *const envp[]);
void Delete_job(jid_t jid);

int builtin_command(struct cmdline_tokens token);
int check_argument(struct cmdline_tokens token);
void process_builtin_jobs(struct cmdline_tokens token);
void process_bgfg(struct cmdline_tokens token, job_state bg_or_fg,
                  sigset_t mask);

/**
 * @brief Sets up the main routine of the shell.
 * This includes redirecting stderr to stdout, parsing command lines, creating
 * the environment variable, initializing the job list, installing relevant
 * handlers, registering a cleaning-up process for termination and executing
 * command lines.
 *
 * @param[in] argc number of command-line arguments
 * @param[in] argv array containing all command-line arguments
 * @return -1 but control never reaches the return statement
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief Evaluates a command-line in the shell, redirecting inputs or outputs
 * if specified, and reports possible parsing or input errors.
 *
 * Relevant errors: invalid command-line, nonexisistent files, mismatched file
 * permissions, failed to fork a child process or execute the user's job, or
 * failed to open/duplicate/close a redirected file.
 *
 * @note If the error occurs in the child process (e.g. fail to open a
 * file), we will call exit to exit the child process (not the shell!). When an
 * error is detected, eval will print the error message.
 *
 * @param[in] cmdline command-line in the shell that will be evaluated/executed
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask_all, prev_one;
    pid_t pid;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    sigemptyset(&mask_all);
    sigfillset(&mask_all);

    // Process non-builtin commands
    if (!builtin_command(token)) {

        // Check file existence and correct file permissions
        if (access(token.argv[0], X_OK | F_OK) < 0) {
            sio_printf("%s: %s\n", token.argv[0], strerror(errno));
            return;
        }

        // Block all signals before forking to avoid racing conditions
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

        if ((pid = fork()) < 0) {
            sio_printf("%s\n", strerror(errno));
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }

        // Child process runs user job
        if (pid == 0) {

            // Ensure that there will be only one foreground process group
            setpgid(0, 0);

            // Input redirection
            if (token.infile != NULL) {
                int fd;
                Open(&fd, token.infile, !MODE_ENABLED, prev_one);
                Dup2(fd, STDIN_FILENO, prev_one);
                Close(fd, prev_one);
            }

            // Output redirection
            if (token.outfile != NULL) {
                int fd;
                Open(&fd, token.outfile, MODE_ENABLED, prev_one);
                Dup2(fd, STDOUT_FILENO, prev_one);
                Close(fd, prev_one);
            }
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            Execve(token.argv[0], token.argv, environ);
            _exit(0);
        }

        // Parent process: only performs operations when jid is valid (> 0)
        // Foreground jobs: wait until terminates
        if (parse_result == PARSELINE_FG) {
            jid_t jobid = add_job(pid, FG, cmdline);
            if (jobid > 0) {
                while (fg_job()) {
                    sigsuspend(&prev_one);
                }
            }
        }

        // Background jobs: print useful message
        else {
            jid_t jobid = add_job(pid, BG, cmdline);
            if (jobid > 0) {
                sio_printf("[%d] (%d) %s\n", jobid, pid, cmdline);
            }
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
        return;
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Processes SIGCHLD signal sent by the kernel and reaps all zombie
 * children available at the current state.
 *
 * A child job enters the handler when it terminates or stops because it
 * received a SIGSTOP or SIGTSTP signal.
 *
 * Relevant errors: Failed to delete a job because of an invalid jid or errno
 * gets corrupted during the process
 *
 * @note Handler doesn't wait for any other currently running children to
 * terminate/change state.
 *
 * If a jobid or a job becomes invalid when it enters the loop, tsh IGNORES it.
 *
 * @param[in] sig signal number that causes a change of state in the child
 */
void sigchld_handler(int sig) {
    // Save and restore errno before returning
    int olderrno = errno;

    sigset_t mask_all, prev_one;
    pid_t pid;
    int wait_status;

    sigemptyset(&mask_all);
    sigfillset(&mask_all);

    // Block all signals to avoid processing new signals on zombie children
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    /* Return 0 if none of the children in the wait set has stopped or
    terminated. Else, return PID of one of the stopped or terminated children */
    while ((pid = waitpid(-1, &wait_status, WNOHANG | WUNTRACED)) > 0) {
        jid_t jobid;
        jobid = job_from_pid(pid);

        // Ignore invalid jid or job
        if (jobid <= 0 || !job_exists(jobid)) {
            continue;
        }

        // Child terminated normally
        if (WIFEXITED(wait_status)) {
            Delete_job(jobid);
        }

        // Child terminated because of an uncaught signal
        else if (WIFSIGNALED(wait_status)) {
            int signal_num = WTERMSIG(wait_status);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jobid, pid,
                       signal_num);
            Delete_job(jobid);
        }

        // Child is currently stopped by signal
        else if (WIFSTOPPED(wait_status)) {
            int signal_num = WSTOPSIG(wait_status);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jobid, pid,
                       signal_num);
            job_set_state(jobid, ST);
        }
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief Processes SIGINT signal (Ctrl-c) and sends it to the foreground job.
 *
 * Relevant error: failed to send SIGINT to the current process group
 *
 * @note SIGINT signal is forwarded to the entire process group that contains
 * the foreground job. If there is no foreground job, SIGINT will have no
 * effect.
 *
 * @param[in] sig signal number that causes a change of state in the child
 */
void sigint_handler(int sig) {
    // Save and restore errno before returning
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    jid_t jobid;

    sigemptyset(&mask_all);
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    // Send signal if foreground job exists
    if ((jobid = fg_job()) != 0) {
        if (kill(-job_get_pid(jobid), SIGINT) != 0) {
            sio_eprintf("%s\n", strerror(errno));
        }
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief Processes SIGTSTP signal (Ctrl-z) and sends it to the foreground job.
 *
 * Relevant error: failed to send SIGTSTP to the current process group
 *
 * @note SIGTSTP signal is forwarded to the entire process group that contains
 * the foreground job. If there is no foreground job, SIGTSTP will have no
 * effect.
 *
 * @param[in] sig signal number that causes a change of state in the child
 */
void sigtstp_handler(int sig) {
    // Save and restore errno before returning
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    jid_t jobid;

    sigemptyset(&mask_all);
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    // Send signal if foreground job exists
    if ((jobid = fg_job()) != 0) {
        if (kill(-job_get_pid(jobid), SIGTSTP) != 0) {
            sio_eprintf("%s\n", strerror(errno));
        }
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
    errno = olderrno;
    return;
}

/*************************
 * Wrappers for Unix I/O
 *************************/

/**
 * @brief This is a wrapper function for the system call open(). It checks the
 * return value of open, converts pathname to a file descriptor and initializes
 * fdptr with the descriptor number if no error is detected.
 *
 * The descriptor number is always the smallest descriptor that is not currently
 * open in the process.
 *
 * @note If the third argument of open() is enabled, it means we are opening an
 * output file. This is because mode only exists when O_CREAT is one of the
 * flags, which happens when we are redirecting to outfile.
 *
 * This wrapper is only used in the child process. We don't use it in the
 * builtin jobs function because we shouldn't exit the shell just because of an
 * invalid filename.
 *
 * @param[in] fdptr pointer that stores the value of file descriptor
 * @param[in] pathname files to be opened
 * @param[in] mode_enabled 1 if open() takes three arguments
 * @param[in] mask unblock masks when exiting the process if errors
 */
void Open(int *fdptr, const char *pathname, int mode_enabled, sigset_t mask) {
    if (mode_enabled) {
        if ((*fdptr = open(pathname, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
            sio_printf("%s : %s\n", pathname, strerror(errno));
            sigprocmask(SIG_SETMASK, &mask, NULL);
            _exit(1);
        }
    } else {
        if ((*fdptr = open(pathname, O_RDONLY)) < 0) {
            sio_printf("%s: %s\n", pathname, strerror(errno));
            sigprocmask(SIG_SETMASK, &mask, NULL);
            _exit(1);
        }
    }
}

/**
 * @brief This is a wrapper function for the system call dup2(). It copies (per-
 * process) descriptor table entry oldfd to entry newfd and reports errors if
 * detected.
 *
 * @note For a similar reason described above, it is only used in the child
 * process.
 *
 * @param[in] oldfd file descriptor entry to be copied
 * @param[in] newfd file descriptor entry that will store oldfd
 * @param[in] mask unblock masks when exiting the process if errors
 */
void Dup2(int oldfd, int newfd, sigset_t mask) {
    if (dup2(oldfd, newfd) < 0) {
        sio_printf("%s\n", strerror(errno));
        sigprocmask(SIG_SETMASK, &mask, NULL);
        _exit(1);
    }
}

/**
 * @brief This is a wrapper function for the system call close(). It closes a
 * file descriptor entry and reports errors if detected.
 *
 * @note For a similar reason described above, it is only used in the child
 * process.
 *
 * @param[in] fd file descriptor entry to be closed
 * @param[in] mask unblock masks when exiting the process if errors
 */
void Close(int fd, sigset_t mask) {
    if (close(fd) < 0) {
        sio_printf("%s\n", strerror(errno));
        sigprocmask(SIG_SETMASK, &mask, NULL);
        _exit(1);
    }
}

/**
 * @brief This is a wrapper function for execve(). It executes filename with
 * arguments specified in argv and environment in envp and reports errors if
 * failed to execute.
 *
 * @param[in] filename program to be executed
 * @param[in] argv array containing all command-line arguments
 * @param[in] envp environment of the new program
 */
void Execve(const char *filename, char *const argv[], char *const envp[]) {
    if (execve(filename, argv, envp) < 0) {
        sio_eprintf("%s: %s\n", filename, strerror(errno));
    }
}

/**
 * @brief This is a wrapper function for delete_job(). It deletes the job
 * specified by jid from the job list or reports errors if failed to do so.
 *
 * @param[in] jid job id of the job that will be deleted
 */
void Delete_job(jid_t jid) {
    if (!delete_job(jid)) {
        sio_eprintf("%s\n", strerror(errno));
    }
}

/******************
 * Builtin commands
 ******************/

/**
 * @brief Checks if the command-line refers to a builtin command (quit/jobs/fg/
 * bg). If so, executes corresponding operations.
 *
 * @param[in] token parsed command line
 * @return 1 if is builtin command
 */
int builtin_command(struct cmdline_tokens token) {
    sigset_t mask_all, prev_one;
    sigemptyset(&mask_all);
    sigfillset(&mask_all);

    // Block all signals because we will access job lists below
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    // Process builtin bg or fg
    if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {

        // Check if the command line contains valid jid or pid
        if (!check_argument(token)) {
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return 1;
        }
        process_bgfg(token, token.builtin == BUILTIN_BG ? BG : FG, prev_one);
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
        return 1;
    }

    // Process builtin quit
    if (token.builtin == BUILTIN_QUIT) {
        _exit(0);
    }
    // Process builtin jobs
    else if (token.builtin == BUILTIN_JOBS) {
        process_builtin_jobs(token);
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
        return 1;
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);

    // Not a builtin command
    return 0;
}

/**
 * @brief Checks if the command line contains enough pid/jid information when
 * processing fg/bg.
 *
 * @note strtoul is used to parse pid/jid from command lines. Though it is not
 * async-signal-safe, it is not used in a signal handler, and all signals have
 * already been blocked before entering the function.
 *
 * @param[in] token parsed command line
 * @return 1 if no errors
 */
int check_argument(struct cmdline_tokens token) {
    // Not enough arguments
    if (token.argc != 2) {
        sio_printf("%s command requires PID or %%jobid argument\n",
                   token.builtin == BUILTIN_BG ? "bg" : "fg");
        return 0;
    }

    char *ptr;
    if (token.argv[1][0] != '%') { // pid
        strtoul(&token.argv[1][0], &ptr, 10);
    } else { // jid
        strtoul(&token.argv[1][1], &ptr, 10);
    }

    // Invalid pid/jid
    if (errno == ERANGE || errno == EINVAL || strlen(ptr) >= 1) {
        sio_printf("%s: argument must be a PID or %%jobid\n",
                   token.builtin == BUILTIN_BG ? "bg" : "fg");
        return 0;
    }
    return 1;
}

/**
 * @brief Processes builtin jobs command, redirecting output if not NULL.
 *
 * @pre Before accessing the function, all signals have been blocked.
 * @param[in] token parsed command line
 */
void process_builtin_jobs(struct cmdline_tokens token) {

    // Redirecting output
    if (token.outfile != NULL) {
        int fd;
        if ((fd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644)) <
            0) {
            sio_printf("%s : %s\n", token.outfile, strerror(errno));
        } else {
            list_jobs(fd);
            if (close(fd) < 0) {
                sio_printf("%s\n", strerror(errno));
            }
        }
    } else {
        list_jobs(STDOUT_FILENO);
    }
}

/**
 * @brief Processes builtin bg/fg command. Resumes jobs and either prints a
 * useful message [bg] or waits until the job finishes [fg].
 *
 * @pre Before accessing the function, all signals have been blocked.
 * @param[in] token parsed command line
 * @param[in] bg_or_fg indicates whether job is fg or bg
 * @param[in] mask temporarily replaces current block set if processing fg
 */
void process_bgfg(struct cmdline_tokens token, job_state bg_or_fg,
                  sigset_t mask) {
    jid_t jobid;
    char *ptr;

    // Parse jid/pid and report error if detected
    if (token.argv[1][0] == '%') {
        jobid = (jid_t)strtoul(&token.argv[1][1], &ptr, 10);
    } else {
        pid_t pid = (pid_t)strtoul(&token.argv[1][0], &ptr, 10);
        jobid = job_from_pid(pid);
    }
    if (errno == ERANGE || errno == EINVAL || strlen(ptr) >= 1 ||
        !job_exists(jobid)) {
        sio_printf("%s: No such job\n", token.argv[1]);
        return;
    }

    // Send signal iff job id is valid
    if (jobid > 0) {
        if (kill(-job_get_pid(jobid), SIGCONT) < 0) {
            sio_printf("%s\n", strerror(errno));
        }
        if (bg_or_fg == BG) {
            job_set_state(jobid, BG);
            sio_printf("[%d] (%d) %s\n", jobid, job_get_pid(jobid),
                       job_get_cmdline(jobid));
        } else {
            job_set_state(jobid, FG);

            // wait for foreground process to exit/terminate
            while (fg_job()) {
                sigsuspend(&mask);
            }
        }
    }
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
