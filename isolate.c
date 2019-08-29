#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <wait.h>
#include <memory.h>
#include <syscall.h>
#include <errno.h>
#include "util.h"
#include "netns.h"

static void prepare_procfs();
static void prepare_mntns(char *rootfs);

struct params {
    int fd[2];
    char **argv;
};

static void parse_args(int argc, char **argv,
                       struct params *params)
{
#define NEXT_ARG() do { argc--; argv++; } while (0)
    // Skip binary path
    NEXT_ARG();

    if (argc < 1) {
        printf("Nothing to do!\n");
        exit(0);
    }

    params->argv = argv;
#undef NEXT_ARG
}

#define STACKSIZE (1024*1024)
static char cmd_stack[STACKSIZE];

void await_setup(int pipe)
{
    // We're done once we read something from the pipe.
    char buf[2];
    if (read(pipe, buf, 2) != 2)
        die("Failed to read from pipe: %m\n");
}

static int cmd_exec(void *arg)
{
    // Kill the cmd process if the isolate process dies.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL))
        die("cannot PR_SET_PDEATHSIG for child process: %m\n");

    struct params *params = (struct params*) arg;
    // Wait for 'setup done' signal from the main process.
    await_setup(params->fd[0]);

    prepare_mntns("rootfs");

    // Assuming, 0 in the current namespace maps to
    // a non-privileged UID in the parent namespace,
    // drop superuser privileges if any by enforcing
    // the exec'ed process runs with UID 0.
    if (setgid(0) == -1)
        die("Failed to setgid: %m\n");
    if (setuid(0) == -1)
        die("Failed to setuid: %m\n");

    char **argv = params->argv;
    char *cmd = argv[0];
    printf("===========%s============\n", cmd);

    if (execvp(cmd, argv) == -1)
        die("Failed to exec %s: %m\n", cmd);

    die("¯\\_(ツ)_/¯");
    return 1;
}

static void write_file(char path[100], char line[100])
{
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        die("Failed to open file %s: %m\n", path);
    }

    if (fwrite(line, 1, strlen(line), f) < 0) {
        die("Failed to write to file %s:\n", path);
    }

    if (fclose(f) != 0) {
        die("Failed to close file %s: %m\n", path);
    }
}

static void prepare_userns(int pid)
{
    char path[100];
    char line[100];

    int uid = 1000;

    sprintf(path, "/proc/%d/uid_map", pid);
    sprintf(line, "0 %d 1\n", uid);
    write_file(path, line);

    sprintf(path, "/proc/%d/setgroups", pid);
    sprintf(line, "deny");
    write_file(path, line);

    sprintf(path, "/proc/%d/gid_map", pid);
    sprintf(line, "0 %d 1\n", uid);
    write_file(path, line);
}

static void prepare_mntns(char *rootfs)
{
    const char *mnt = rootfs;

    if (mount(rootfs, mnt, "ext4", MS_BIND, ""))
        die("Failed to mount %s at %s: %m\n", rootfs, mnt);

    if (chdir(mnt))
        die("Failed to chdir to rootfs mounted at %s: %m\n", mnt);

    const char *put_old = ".put_old";
    if (mkdir(put_old, 0777) && errno != EEXIST)
        die("Failed to mkdir put_old %s: %m\n", put_old);

    if (syscall(SYS_pivot_root, ".", put_old))
        die("Failed to pivot_root from %s to %s: %m\n", rootfs, put_old);

    if (chdir("/"))
        die("Failed to chdir to new root: %m\n");

    prepare_procfs();

    if (umount2(put_old, MNT_DETACH))
        die("Failed to umount put_old %s: %m\n", put_old);
}

static void prepare_procfs()
{
    if (mkdir("/proc", 0555) && errno != EEXIST)
        die("Failed to mkdir /proc: %m\n");

    if (mount("proc", "/proc", "proc", 0, ""))
        die("Failed to mount proc: %m\n");
}

static void prepare_netns(int cmd_pid)
{
    char *veth = "veth0";
    char *vpeer = "veth1";
    char *veth_addr = "10.1.1.1";
    char *vpeer_addr = "10.1.1.2";
    char *netmask = "255.255.255.0";

    int sock_fd = create_socket(
            PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

    create_veth(sock_fd, veth, vpeer);

    if_up(veth, veth_addr, netmask);

    int mynetns = get_netns_fd(getpid());
    int child_netns = get_netns_fd(cmd_pid);

    move_if_to_pid_netns(sock_fd, vpeer, child_netns);

    if (setns(child_netns, CLONE_NEWNET))
        die("Failed to setns for command at pid %d: %m\n", cmd_pid);

    if_up(vpeer, vpeer_addr, netmask);

    if (setns(mynetns, CLONE_NEWNET))
        die("Failed to restore previous net namespace: %m\n");

    close(sock_fd);
}

int main(int argc, char **argv)
{

    struct params params;
    memset(&params, 0, sizeof(struct params));

    parse_args(argc, argv, &params);

    // Create pipe to communicate between main and command process.
    if (pipe(params.fd) < 0)
        die("Failed to create pipe: %m");

    // Clone command process.
    int clone_flags =
            // if the command process exits, it leaves an exit status
            // so that we can reap it.
            SIGCHLD |
            CLONE_NEWUTS | CLONE_NEWUSER |
            CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET;
    int cmd_pid = clone(
        cmd_exec, cmd_stack + STACKSIZE, clone_flags, &params);

    if (cmd_pid < 0)
        die("Failed to clone: %m\n");

    // Get the writable end of the pipe.
    int pipe = params.fd[1];

    prepare_userns(cmd_pid);
    prepare_netns(cmd_pid);

    // Signal to the command process we're done with setup.
    if (write(pipe, "OK", 2) != 2)
        die("Failed to write to pipe: %m");
    if (close(pipe))
        die("Failed to close pipe: %m");

    if (waitpid(cmd_pid, NULL, 0) == -1)
        die("Failed to wait pid %d: %m\n", cmd_pid);

    return 0;
}
