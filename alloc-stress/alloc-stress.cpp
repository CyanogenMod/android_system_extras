#include <arpa/inet.h>
#include <iostream>
#include <chrono>
#include <cutils/sockets.h>
#include <hardware/gralloc.h>
#include <vector>
#include <tuple>
#include <algorithm>
#include <tuple>
#include <numeric>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <sys/wait.h>

using namespace std;

#define ASSERT_TRUE(cond) \
do { \
    if (!(cond)) {\
       cerr << __func__ << "( " << getpid() << "):" << __LINE__ << " condition:" << #cond << " failed\n" << endl; \
       exit(EXIT_FAILURE); \
    } \
} while (0)

class Pipe {
    int m_readFd;
    int m_writeFd;
    Pipe(const Pipe &) = delete;
    Pipe& operator=(const Pipe &) = delete;
    Pipe& operator=(const Pipe &&) = delete;
public:
    Pipe(int readFd, int writeFd) : m_readFd{readFd}, m_writeFd{writeFd} {
        fcntl(m_readFd, F_SETFD, FD_CLOEXEC);
        fcntl(m_writeFd, F_SETFD, FD_CLOEXEC);
    }
    Pipe(Pipe&& rval) noexcept {
        m_readFd = rval.m_readFd;
        m_writeFd = rval.m_writeFd;
        rval.m_readFd = 0;
        rval.m_writeFd = 0;
    }
    ~Pipe() {
        if (m_readFd)
            close(m_readFd);
        if (m_writeFd)
            close(m_writeFd);
    }
    void preserveOverFork(bool preserve) {
        if (preserve) {
            fcntl(m_readFd, F_SETFD, 0);
            fcntl(m_writeFd, F_SETFD,0);
        } else {
            fcntl(m_readFd, F_SETFD, FD_CLOEXEC);
            fcntl(m_writeFd, F_SETFD, FD_CLOEXEC);
        }
    }
    int getReadFd() {
        return m_readFd;
    }
    int getWriteFd() {
        return m_writeFd;
    }
    void signal() {
        bool val = true;
        int error = write(m_writeFd, &val, sizeof(val));
        ASSERT_TRUE(error == sizeof(val));
    };
    void wait() {
        bool val = false;
        int error = read(m_readFd, &val, sizeof(val));
        ASSERT_TRUE(error == sizeof(val));
    }
    bool wait_ret_error() {
        bool val = false;
        int error = read(m_readFd, &val, sizeof(val));
        return (error != 1);
    }
    template <typename T> void send(const T& v) {
        int error = write(m_writeFd, &v, sizeof(T));
        ASSERT_TRUE(error >= 0);
    }
    template <typename T> void recv(T& v) {
        int error = read(m_readFd, &v, sizeof(T));
        ASSERT_TRUE(error >= 0);
    }
    static Pipe makePipeFromFds(int readFd, int writeFd) {
        return Pipe(readFd, writeFd);
    }
    static tuple<Pipe, Pipe> createPipePair() {
        int a[2];
        int b[2];

        int error1 = pipe(a);
        int error2 = pipe(b);
        ASSERT_TRUE(error1 >= 0);
        ASSERT_TRUE(error2 >= 0);

        return make_tuple(Pipe(a[0], b[1]), Pipe(b[0], a[1]));
    }
};

void createProcess(Pipe pipe, const char *exName, const char *arg)
{
    pipe.preserveOverFork(true);
    pid_t pid = fork();
    // child proc
    if (pid == 0) {
        char readFdStr[16];
        char writeFdStr[16];
        snprintf(readFdStr, sizeof(readFdStr), "%d", pipe.getReadFd());
        snprintf(writeFdStr, sizeof(writeFdStr), "%d", pipe.getWriteFd());
        execl(exName, exName, "--worker", arg, readFdStr, writeFdStr, 0);
        ASSERT_TRUE(0);
    }
    // parent process
    else if (pid > 0) {
        pipe.preserveOverFork(false);
        return;
    }
    else {
        ASSERT_TRUE(0);
    }
}


static void write_oomadj_to_lmkd(int oomadj) {
    // Connect to lmkd and store our oom_adj
    int lmk_procprio_cmd[4];
    int sock;
    int tries = 10;
    while ((sock = socket_local_client("lmkd",
                    ANDROID_SOCKET_NAMESPACE_RESERVED,
                    SOCK_SEQPACKET)) < 0) {
        usleep(100000);
        if (tries-- < 0) break;
    }
    if (sock < 0) {
        cout << "Failed to connect to lmkd, errno " << errno << endl;
        exit(1);
    }
    lmk_procprio_cmd[0] = htonl(1);
    lmk_procprio_cmd[1] = htonl(getpid());
    lmk_procprio_cmd[2] = htonl(getuid());
    lmk_procprio_cmd[3] = htonl(oomadj);

    int written = write(sock, lmk_procprio_cmd, sizeof(lmk_procprio_cmd));
    cout << "Wrote " << written << " bytes to lmkd control socket." << endl;
}

#ifdef ENABLE_MEM_CGROUPS
static void create_memcg() {
    char buf[256];
    pid_t pid = getpid();
    snprintf(buf, sizeof(buf), "/dev/memctl/apps/%u", pid);

    int tasks = mkdir(buf, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (tasks < 0) {
        cout << "Failed to create memory cgroup" << endl;
        return;
    }
    snprintf(buf, sizeof(buf), "/dev/memctl/apps/%u/tasks", pid);
    tasks = open(buf, O_WRONLY);
    if (tasks < 0) {
        cout << "Unable to add process to memory cgroup" << endl;
        return;
    }
    snprintf(buf, sizeof(buf), "%u", pid);
    write(tasks, buf, strlen(buf));
    close(tasks);
}
#endif

size_t s = 4 * (1 << 20);
void *gptr;
int main(int argc, char *argv[])
{
    if ((argc > 1) && (std::string(argv[1]) == "--worker")) {
#ifdef ENABLE_MEM_CGROUPS
        create_memcg();
#endif
        write_oomadj_to_lmkd(atoi(argv[2]));
        Pipe p{atoi(argv[3]), atoi(argv[4])};

        long long allocCount = 0;
        while (1) {
            p.wait();
            char *ptr = (char*)malloc(s);
            memset(ptr, (int)allocCount >> 10, s);
            for (int i = 0; i < s; i+= 4096) {
                *((long long*)&ptr[i]) = allocCount + i;
            }
            usleep(10 * 1000);
            gptr = ptr;
            //cout << "total alloc: " << allocCount / (1<<20)<< " adj: " << argv[2]<< endl;;
            //cout << "ptr: " << (long long)(void*)ptr << endl;;
            p.signal();
            allocCount += s;
        }
    } else {
        cout << "parent:" << argc << endl;

        write_oomadj_to_lmkd(-1000);
        for (int i = 1000; i >= 0; i -= 100) {
            auto pipes = Pipe::createPipePair();
            char arg[16];
            snprintf(arg, sizeof(arg), "%d", i);
            createProcess(std::move(std::get<1>(pipes)), argv[0], arg);
            Pipe &p = std::get<0>(pipes);

            size_t t = 0;
            while (1) {
                //;cout << getpid() << ":" << "parent signal" << endl;
                p.signal();
                if (p.wait_ret_error()) {
                    int status;
                    waitpid(0, &status, 0);
                    break;
                }
                t += s;
            }
            cout << "adj: " << i << " sz: " << t / (1 << 20) << endl;
        }
    }
    return 0;
}
