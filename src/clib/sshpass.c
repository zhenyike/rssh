#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define PACKAGE_NAME "sshpass"
#define PASSWORD_PROMPT "assword"

extern char *ptsname(int fd);

enum program_return_codes {
    RETURN_NOERROR,                 // 0. 正常退出
    RETURN_INVALID_ARGUMENTS,       // 1. 参数不可用
    RETURN_CONFLICTING_ARGUMENTS,   // 2. 参数冲突
    RETURN_RUNTIME_ERROR,           // 3. 运行时错误
    RETURN_PARSE_ERRROR,            // 4. 解析错误
    RETURN_INCORRECT_PASSWORD,      // 5. 密码错误
    RETURN_HOST_KEY_UNKNOWN,        // 6. 主机 key 未知
    RETURN_HOST_KEY_CHANGED,        // 7. 主机 key 已改变
};

int runprogram( int argc, char *argv[] );

struct {
    enum { PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS } pwtype;
    union {
        const char *filename;
        int fd;
        const char *password;
    } pwsrc;

    const char *pwprompt;
    int verbose;
} args;

void show_help()
{
    printf("Usage: " PACKAGE_NAME " [-f|-d|-p|-e] [-hV] command parameters\n"
            "   -f filename   Take password to use from file\n"
            "   -d number     Use number as file descriptor for getting password\n"
            "   -p password   Provide password as argument (security unwise)\n"
            "   -e            Password is passed as env-var \"SSHPASS\"\n"
            "   With no parameters - password will be taken from stdin\n\n"
            "   -P prompt     Which string should sshpass search for to detect a password prompt\n"
            "   -v            Be verbose about what you're doing\n"
            "   -h            Show help (this screen)\n"
            "   -V            Print version information\n"
            "At most one of -f, -d, -p or -e should be used\n");
}

int handleoutput( int fd );

/* Global variables so that this information be shared with the signal handler */
int ourtty; // Our own tty
int masterpt;

void window_resize_handler(int signum);
void sigchld_handler(int signum);

int runprogram( int argc, char *argv[] )
{
    struct winsize ttysize;                         // 设置 tty 窗口大小

    // We need to interrupt a select with a SIGCHLD. In order to do so, we need a SIGCHLD handler
    signal(SIGCHLD, sigchld_handler);

    masterpt = posix_openpt(O_RDWR);                // 打开主伪终端
    if(masterpt == -1) {
        perror("Failed to get a pseudo terminal");
        return RETURN_RUNTIME_ERROR;
    }

    fcntl(masterpt, F_SETFL, O_NONBLOCK);           // 设置 tty 为非阻塞

    if(grantpt(masterpt) != 0) {                    // 设置对应从设备权限
        perror("Failed to change pseudo terminal's permission");
        return RETURN_RUNTIME_ERROR;
    }
    if(unlockpt(masterpt) != 0) {                  // 清除从设备内部锁
        perror("Failed to unlock pseudo terminal");
        return RETURN_RUNTIME_ERROR;
    }

    ourtty = open("/dev/tty", 0);                   // 打开 tty 并设置窗口大小
    if(ourtty != -1 && ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0 ) {
        signal(SIGWINCH, window_resize_handler);
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    }

    const char *name = ptsname(masterpt);           // 获得伪终端名
    int slavept;
    int childpid = fork();
    if( childpid == 0 ) {
        /* 子进程 */
        setsid();                                   // 与父进程脱离
        slavept = open(name, O_RDWR);               // 读写方式打开伪终端
        close(slavept);
        close(masterpt);

        char **new_argv = malloc(sizeof(char *)*(argc + 1));
        int i;
        for(i = 0; i < argc; ++i) {
            new_argv[i] = argv[i];
        }

        new_argv[i] = NULL;

        execvp(new_argv[0], new_argv);              // 执行程序, new_argv 为参数列表, 最后一个必须为 NULL
                                                    // 执行成功后会直接结束当前进程, 新建一个进程执行程序
        perror("sshpass: Failed to run command");
        exit(RETURN_RUNTIME_ERROR);
    } else if(childpid < 0) {                       // 启动子进程失败
        perror("sshpass: Failed to create child process");
        return RETURN_RUNTIME_ERROR;
    }

    /* 父进程 */
    slavept = open(name, O_RDWR | O_NOCTTY);

    int status = 0;
    int terminate = 0;
    pid_t wait_id;

    sigset_t sigmask, sigmask_select;

    sigemptyset(&sigmask_select);                   // 初始化信号集
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);                   // SIGCHLD (终止信号) 添加到信号集 sigmask
    sigprocmask(SIG_SETMASK, &sigmask, NULL);

    do {
        if( !terminate ) {
            fd_set readfd;

            FD_ZERO(&readfd);                       // 初始化 readfd
            FD_SET(masterpt, &readfd);              // 将主设备配置加到 readfd

            int selret = pselect(masterpt+1, &readfd, NULL, NULL, NULL, &sigmask_select);

            if( selret > 0 ) {
                if( FD_ISSET( masterpt, &readfd ) ) {
                    int ret;
                    if( (ret = handleoutput( masterpt )) ) {
                        if( ret>0 ) {
                            close( masterpt ); // Signal ssh that it's controlling TTY is now closed
                            close(slavept);
                        }

                        terminate=ret;

                        if( terminate ) {
                            close( slavept );
                        }
                    }
                }
            }
            wait_id = waitpid(childpid, &status, WNOHANG);
        } else {
            wait_id = waitpid( childpid, &status, 0 );
        }
    } while( wait_id==0 || (!WIFEXITED( status ) && !WIFSIGNALED( status )) );

    if( terminate>0 )
        return terminate;
    else if( WIFEXITED( status ) )
        return WEXITSTATUS(status);
    else
        return 255;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state );
void write_pass( int fd );

int handleoutput( int fd )
{
    // We are looking for the string
    int prevmatch = 0; // If the "password" prompt is repeated, we have the wrong password.
    int state1, state2;
    int firsttime = 1;
    const char *compare1 = PASSWORD_PROMPT; // Asking for a password
    const char compare2[] = "The authenticity of host "; // Asks to authenticate host
    // static const char compare3[]="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"; // Warns about man in the middle attack
    // The remote identification changed error is sent to stderr, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    char buffer[256];
    int ret=0;

    if( args.pwprompt ) {
        compare1 = args.pwprompt;
    }

    if( args.verbose && firsttime ) {
        firsttime=0;
        fprintf(stderr, "SSHPASS searching for password prompt using match \"%s\"\n", compare1);
    }

    int numread=read(fd, buffer, sizeof(buffer)-1 );
    buffer[numread] = '\0';
    if( args.verbose ) {
        fprintf(stderr, "SSHPASS read: %s\n", buffer);
    }

    state1=match( compare1, buffer, numread, state1 );

    // Are we at a password prompt?
    if( compare1[state1]=='\0' ) {
        if( !prevmatch ) {
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected prompt. Sending password.\n");
            write_pass( fd );
            state1=0;
            prevmatch=1;
        } else {
            // Wrong password - terminate with proper error code
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected prompt, again. Wrong password. Terminating.\n");
            ret=RETURN_INCORRECT_PASSWORD;
        }
    }

    if( ret==0 ) {
        state2=match( compare2, buffer, numread, state2 );

        // Are we being prompted to authenticate the host?
        if( compare2[state2]=='\0' ) {
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected host authentication prompt. Exiting.\n");
            ret=RETURN_HOST_KEY_UNKNOWN;
        }
    }

    return ret;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state )
{
    // This is a highly simplisic implementation. It's good enough for matching "Password: ", though.
    int i;
    for( i=0;reference[state]!='\0' && i<bufsize; ++i ) {
        if( reference[state]==buffer[i] )
            state++;
        else {
            state=0;
            if( reference[state]==buffer[i] )
                state++;
        }
    }

    return state;
}

void write_pass_fd( int srcfd, int dstfd );

void write_pass( int fd )
{
    switch( args.pwtype ) {
    case PWT_STDIN:
        write_pass_fd( STDIN_FILENO, fd );
        break;
    case PWT_FD:
        write_pass_fd( args.pwsrc.fd, fd );
        break;
    case PWT_FILE:
        {
            int srcfd=open( args.pwsrc.filename, O_RDONLY );
            if( srcfd!=-1 ) {
                write_pass_fd( srcfd, fd );
                close( srcfd );
            }
        }
        break;
    case PWT_PASS:
        write( fd, args.pwsrc.password, strlen( args.pwsrc.password ) );
        write( fd, "\n", 1 );
        break;
    }
}

void write_pass_fd( int srcfd, int dstfd )
{

    int done=0;

    while( !done ) {
        char buffer[40];
        int i;
        int numread=read( srcfd, buffer, sizeof(buffer) );
        done=(numread<1);
        for( i=0; i<numread && !done; ++i ) {
            if( buffer[i]!='\n' )
                write( dstfd, buffer+i, 1 );
            else
                done=1;
        }
    }

    write( dstfd, "\n", 1 );
}

void window_resize_handler(int signum)
{
    struct winsize ttysize; // The size of our tty

    if(ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0) {
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    }
}

// Do nothing handler - makes sure the select will terminate if the signal arrives, though.
void sigchld_handler(int signum)
{
}

/* 运行程序, 供外部调用 */
int run_main(char *ip_user, char *password, char *cmd)
{
    args.pwtype = PWT_PASS;
    args.pwsrc.password = (char *) malloc(20 * sizeof(char));
    strcpy((char *)args.pwsrc.password, password);

    int argc = 6;
    char *argv[7];
    argv[0] = (char *) malloc(5 * sizeof(char));
    argv[1] = (char *) malloc(30 * sizeof(char));
    argv[2] = (char *) malloc(5 * sizeof(char));
    argv[3] = (char *) malloc(30 * sizeof(char));
    argv[4] = (char *) malloc(5 * sizeof(char));
    argv[5] = (char *) malloc(30 * sizeof(char));

    strcpy(argv[0], "ssh");
    strcpy(argv[1], ip_user);
    strcpy(argv[2], "-o");
    strcpy(argv[3], "StrictHostKeyChecking=no");
    strcpy(argv[4], "-o");
    strcpy(argv[5], "ConnectTimeout=2");

    int cmd_len = strlen(cmd);
    if (cmd_len > 0) {
        argv[6] = (char *) malloc((cmd_len + 1) * sizeof(char));
        strcpy(argv[6], cmd);
        argc += 1;
    }
    int re = runprogram( argc, argv);

    free(argv[0]);
    free(argv[1]);
    free(argv[2]);
    free(argv[3]);
    free(argv[4]);
    free(argv[5]);
    free((char *)args.pwsrc.password);

    if (cmd_len > 0) {
        free(argv[6]);
    }

    return re;
}

/* 验证密码, 供外部调用 */
int verify_pwd(char *ip_user, char *password)
{
    args.pwtype = PWT_PASS;
    args.pwsrc.password = (char *) malloc(20 * sizeof(char));
    strcpy((char *)args.pwsrc.password, password);

    int argc = 6;
    char *argv[6];
    argv[0] = (char *) malloc(5 * sizeof(char));
    argv[1] = (char *) malloc(30 * sizeof(char));
    argv[2] = (char *) malloc(5 * sizeof(char));
    argv[3] = (char *) malloc(30 * sizeof(char));
    argv[4] = (char *) malloc(15 * sizeof(char));
    argv[5] = (char *) malloc(5 * sizeof(char));

    strcpy(argv[0], "ssh");
    strcpy(argv[1], ip_user);
    strcpy(argv[2], "-o");
    strcpy(argv[3], "StrictHostKeyChecking=no");
    strcpy(argv[4], "pwd>/dev/null");
    strcpy(argv[5], "2>&1");

    int re = runprogram(argc, argv);
    free(argv[0]);
    free(argv[1]);
    free(argv[2]);
    free(argv[3]);
    free(argv[4]);
    free(argv[5]);
    free((char *)args.pwsrc.password);
    return re;
}
