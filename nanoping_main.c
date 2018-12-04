#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <assert.h>
#include <stdatomic.h>
#include "nanoping.h"

enum nanoping_mode {
    mode_none = 0,
    mode_server,
    mode_client
};

static struct option longopts[] = {
    {"interface", required_argument, NULL, 'i'},
    {"count",   required_argument,  NULL,  'n'},
    {"delay",   required_argument,  NULL,  'd'},
    {"port",    required_argument,  NULL,  'p'},
    {"log",     required_argument,  NULL,   'l'},
    {"emulation",   no_argument,    NULL,   'e'},
    {"ptpmode", no_argument,        NULL,   'P'},
    {"silent",  no_argument,        NULL,   's'},
    {"timeout", required_argument,  NULL,   't'},
    {"busypoll", required_argument, NULL,   'b'},
    {"dummy-pkt", required_argument, NULL, 'x'},
    {"help",    no_argument,        NULL,   'h'},
    {0,         0,                  0,  0}
};

static atomic_bool signal_initialized = ATOMIC_VAR_INIT(false);
static atomic_bool signal_handled = ATOMIC_VAR_INIT(false);
static _Atomic enum nanoping_msg_type state = ATOMIC_VAR_INIT(msg_none);
static pthread_mutex_t process_lock, signal_lock;
static pthread_cond_t process_cond, signal_cond;
static pthread_t signal_thread = 0;
static void usage(void)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  client: nanoping --client --interface [nic] --count [sec] --delay [usec] --port [port] --log [log] --emulation --ptpmode --silent --timeout [usec] --busypoll [usec] --dummy-pkt [cnt] [host]\n");
    fprintf(stderr, "  server: nanoping --server --interface [nic] --port [port] --emulation --ptpmode --silent --timeout [usec] --busypoll [usec] --dummy-pkt [cnt]\n");
}

static struct {
    unsigned long delta_t_calculated;
    struct nanoping_timeval min, max, sum;
    pthread_mutex_t lock;
} stats = {0};

static void update_statistics(struct nanoping_timeval delta_t)
{
    pthread_mutex_lock(&stats.lock);
    struct nanoping_timeval sum_prev =  stats.sum;
    if ((stats.min.tv_sec == 0 && stats.min.tv_nsec == 0) ||
        timevalcmp(&stats.min, &delta_t, >))
        stats.min = delta_t;
    if (timevalcmp(&stats.max, &delta_t, <))
        stats.max = delta_t;
    timevaladd(&stats.sum, &delta_t, &stats.sum);
    if (timevalcmp(&stats.sum, &sum_prev, <)) {
        fprintf(stderr, "Overflow detected on avg calculation!\n");
        exit(1);
    }
    stats.delta_t_calculated++;
    pthread_mutex_unlock(&stats.lock);
}

inline static double percent_ulong(unsigned long v1, unsigned long v2)
{
    return (((double)(v1 - v2)) * 100) / v1;
}

#define timevalprint_ns(tvp) \
    do { \
        if ((tvp)->tv_sec) \
            printf("%ld", (tvp)->tv_sec); \
        printf("%ld", (tvp)->tv_nsec); \
    } while (0)

#define timevalprint_s(tvp) \
    do { \
        if ((tvp)->tv_sec) \
            printf("%ld.", (tvp)->tv_sec); \
        else \
            printf("0."); \
        printf("%ld", (tvp)->tv_nsec); \
    } while (0)

static void dump_statistics(struct nanoping_instance *ins, struct timespec *duration, bool client, size_t size)
{
    assert(ins);
    assert(duration);

    pthread_mutex_lock(&stats.lock);
    printf("--- nanoping statistics ---\n");
    printf("packet size %zd bytes\n",
            size);
    printf("%lu packets transmitted, %lu received, ",
            ins->pkt_transmitted,
            ins->pkt_received);
    if (client)
	    printf("%f%% packet loss, ",
            percent_ulong(ins->pkt_transmitted, ins->pkt_received));
    printf("time ");
    timevalprint_s(duration);
    printf(" s\n");
    printf("%lu RX stamp collected, %lu TX stamp collected\n",
            ins->rxs_collected,
            ins->txs_collected);
    printf("RX: found %lu previous RX stamp, found %lu previous TX stamp\n",
            ins->rx_prev_rxs_found,
            ins->rx_prev_txs_found);
    printf("TX: found %lu previous RX stamp, found %lu previous TX stamp\n",
            ins->tx_prev_rxs_found,
            ins->tx_prev_txs_found);
    printf("TX: TX stamp too late %lu\n",
	    ins->tx_prev_txs_too_late);
    printf("%lu Remote RX stamp collected, %lu Remote TX stamp collected\n",
            ins->rem_rxs_collected,
            ins->rem_txs_collected);
    if (client) {
        printf("%lu delta_t calculated\n",
                stats.delta_t_calculated);
        printf("swd min/avg/max = ");
        timevalprint_ns(&stats.min);
        printf("/");
        struct nanoping_timeval avg = stats.sum;
        timevaldiv2(&avg, stats.delta_t_calculated);
        timevalprint_ns(&avg);
        printf("/");
        timevalprint_ns(&stats.max);
        printf(" ns\n");
    }
    pthread_mutex_unlock(&stats.lock);
}

struct client_task_arg {
    struct nanoping_instance *ins;
    char *host;
    FILE *log;
    bool silent;
};

static void *process_client_receive_task(void *arg)
{
    struct client_task_arg *clarg = (struct client_task_arg *)arg;
    struct nanoping_instance *ins = clarg->ins;
    struct nanoping_receive_result receive_result = {0};
    ssize_t siz;


    nanoping_wait_for_receive(ins);
    for (;;) {
        siz = nanoping_receive_one(ins, &receive_result);
        if (siz < 0)
            exit(EXIT_FAILURE);

        switch (receive_result.type) {
            case msg_syn_ack:
                atomic_store(&state, msg_syn_ack);
                break;
            case msg_syn_rst:
                atomic_store(&state, msg_syn_rst);
                fprintf(stderr, "Remote node rejected connection\n");
                break;
            case msg_pong:
                if (atomic_load(&state) != msg_ping)
                    break;
                pthread_mutex_lock(&process_lock);
                pthread_cond_signal(&process_cond);
                pthread_mutex_unlock(&process_lock);
                break;
            case msg_fin_ack:
                atomic_store(&state, msg_fin_ack);
                break;
            case msg_dummy:
                /* do nothing */
                break;
            default:
                fprintf(stderr, "unknown message received\n");
        }
    }
    return NULL;
}

static void *process_client_proc_task(void *arg)
{
    struct client_task_arg *clarg = (struct client_task_arg *)arg;
    struct nanoping_instance *ins = clarg->ins;
    FILE *log = clarg->log;
    char *host = clarg->host;
    struct nanoping_process_result process_result = {0};
    uint64_t prev_seq;

    for (;;) {
        struct nanoping_timeval t3_t0, t2_t1, sum, delta_t;
        int res = nanoping_process_one(ins, &process_result);
        prev_seq = process_result.seq - 1;
        if (res < 0) {
            if (process_result.error & rxerr_rxs_failed) {
                logprintf(log, "%lu,rxs_failed\n", process_result.seq);
                fprintf(stderr, "rx stamp failed on seq %lu\n",
                        process_result.seq);
            }
            if (process_result.error & rxerr_rem_rxs_failed) {
                logprintf(log, "%lu,rem_rxs_failed\n", prev_seq);
                fprintf(stderr, "remote rx stamp failed on seq %lu\n",
                        prev_seq);
            }
            if (process_result.error & rxerr_rem_txs_failed) {
                logprintf(log, "%lu,rem_txs_failed\n", prev_seq);
                fprintf(stderr, "remote tx stamp failed on seq %lu\n",
                        prev_seq);
            }
            if (process_result.error & rxerr_rx_dropped) {
                logprintf(log, "%lu,rx_dropped\n", prev_seq);
                fprintf(stderr, "rxs record dropped on seq %lu\n",
                        prev_seq);
            }
            if (process_result.error & rxerr_tx_dropped) {
                logprintf(log, "%lu,tx_dropped\n", prev_seq);
                fprintf(stderr, "txs record dropped on seq %lu\n",
            prev_seq);
            }
            continue;
        } else if (res == 0) {
            pthread_mutex_lock(&process_lock);
            pthread_cond_wait(&process_cond, &process_lock);
            pthread_mutex_unlock(&process_lock);
            continue;
        }

        if (prev_seq == 0)
            continue;

        // delta_t = ((t3 - t0) - (t2 - t1)) / 2
        timevalsub(&process_result.t3, &process_result.t0, &t3_t0);
        timevalsub(&process_result.t2, &process_result.t1, &t2_t1);
        timevalsub(&t3_t0, &t2_t1, &sum);
        delta_t = sum;
        timevaldiv2(&delta_t, 2);

        if (!clarg->silent) {
            printf("%s: seq=%lu time=", host, prev_seq);
            timevalprint_ns(&delta_t);
            printf("ns\n");
        }
        logprintf(log, "%lu,ok,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%d\n",
            prev_seq,
            process_result.t0.tv_sec, process_result.t0.tv_nsec,
            process_result.t1.tv_sec, process_result.t1.tv_nsec,
            process_result.t2.tv_sec, process_result.t2.tv_nsec,
            process_result.t3.tv_sec, process_result.t3.tv_nsec,
            t3_t0.tv_sec, t3_t0.tv_nsec,
            t2_t1.tv_sec, t2_t1.tv_nsec,
            sum.tv_sec, sum.tv_nsec,
            delta_t.tv_sec, delta_t.tv_nsec,
            process_result.num_txs);
        update_statistics(delta_t);
    }
    return NULL;
}

static void *process_client_signal_task(void *arg)
{
    sigset_t sigmask = *(sigset_t *)arg;

    if (sigprocmask(SIG_SETMASK, &sigmask, NULL) < 0) {
        perror("sigprocmask");
        return NULL;
    }

    atomic_store(&signal_initialized, true);
    pthread_mutex_lock(&signal_lock);
    pthread_cond_signal(&signal_cond);
    pthread_mutex_unlock(&signal_lock);
    for (;;) {
        int sig;
        enum nanoping_msg_type s;
        if (sigwait(&sigmask, &sig) < 0) {
            perror("sigwait");
            return NULL;
        }
        switch (sig) {
            case SIGINT:
            case SIGALRM:
                s = atomic_load(&state);
                switch (s) {
                    case msg_none:
                    case msg_syn:
                    case msg_syn_ack:
                    case msg_syn_rst:
                        exit(EXIT_FAILURE);
                    default:
                        atomic_store(&signal_handled, true);
                }
                break;
        }
    }
}

static void *process_txs_task(void *arg)
{
    struct nanoping_instance *ins = (struct nanoping_instance *)arg;

    for (;;)
        nanoping_txs_one(ins);
    return NULL;
}

static int run_client(struct nanoping_instance *ins, int count, int delay, char *host, char *port, char *logpath, bool silent, int dummy_pkt)
{
    int i;
    struct client_task_arg carg = {0};
    struct nanoping_send_request send_request = {0};
    struct addrinfo *reminfo;
    pthread_t receive_thread = 0, process_thread = 0, txs_thread = 0;
    struct timespec started, finished, duration;
    ssize_t pktsize = 0;
    ssize_t siz;
    int res;
    FILE *log = NULL;
    sigset_t sigmask;

    pthread_mutex_init(&signal_lock, NULL);
    pthread_cond_init(&signal_cond, NULL);

    if (sigemptyset(&sigmask) < 0) {
        perror("sigemptyset");
        return EXIT_FAILURE;
    }
    if (sigaddset(&sigmask, SIGINT) < 0) {
        perror("sigaddset");
        return EXIT_FAILURE;
    }
    if (sigaddset(&sigmask, SIGALRM) < 0) {
        perror("sigaddset");
        return EXIT_FAILURE;
    }
    if (sigprocmask(SIG_SETMASK, &sigmask, NULL) < 0) {
        perror("sigprocmask");
        return EXIT_FAILURE;
    }
    if (pthread_create(&signal_thread, NULL, process_client_signal_task, &sigmask) < 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }
    if (pthread_detach(signal_thread) < 0) {
        perror("pthread_detach");
        return EXIT_FAILURE;
    }

    if (!atomic_load(&signal_initialized)) {
        pthread_mutex_lock(&signal_lock);
        pthread_cond_wait(&signal_cond, &signal_lock);
        pthread_mutex_unlock(&signal_lock);
    }

    pthread_mutex_init(&process_lock, NULL);
    pthread_cond_init(&process_cond, NULL);

    printf("nanoping %s:%s...\n", host, port);
    if ((res = getaddrinfo(host, port, NULL, &reminfo)) < 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        return EXIT_FAILURE;
    }

    if ((res = clock_gettime(CLOCK_MONOTONIC, &started))) {
        perror("clock_gettime");
        return res;
    }

    if (logpath) {
        if ((log = fopen(logpath, "w")) == NULL) {
            perror("fopen");
            return EXIT_FAILURE;
        }
    }

    logprintf(log, "seq,stat,t0,t1,t2,t3,t3-t0,t2-t1,sum,delta_t,num_txs\n");

    carg.ins = ins;
    carg.log = log;
    carg.host = host;
    carg.silent = silent;

    if (pthread_create(&receive_thread, NULL, process_client_receive_task, &carg) < 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    if (pthread_create(&process_thread, NULL, process_client_proc_task, &carg) < 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    if (pthread_create(&txs_thread, NULL, process_txs_task, ins) < 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    if (count) {
        alarm(count);
    }

    atomic_store(&state, msg_syn);
    memcpy(&send_request.remaddr, reminfo->ai_addr,
            sizeof(send_request.remaddr));
    send_request.type = msg_syn;
    send_request.seq = 0;
    for(bool first_time = true;;) {
        if (nanoping_send_one(ins, &send_request) < 0) {
            return EXIT_FAILURE;
        }
        if (first_time) {
            first_time = false;
            usleep(50000);
        }else{
            usleep(500000);
        }
        if (atomic_load(&state) != msg_syn)
            break;
    }

    if (atomic_load(&state) != msg_syn_ack)
        return EXIT_FAILURE;

    atomic_store(&state, msg_ping);
    memcpy(&send_request.remaddr, reminfo->ai_addr,
            sizeof(send_request.remaddr));
    send_request.type = msg_ping;
    for (i = 1; !atomic_load(&signal_handled); i++) {
        send_request.seq = i;
        siz = nanoping_send_one(ins, &send_request);
        if (siz < 0)
            return EXIT_FAILURE;
        if (!pktsize)
            pktsize = siz;
        if (delay >= 0)
            usleep(delay);
        if (dummy_pkt) {
            struct nanoping_send_dummies_request dummies_request;
            memcpy(&dummies_request.remaddr, reminfo->ai_addr,
                sizeof(dummies_request.remaddr));
            dummies_request.nmsg = dummy_pkt;

            res = nanoping_send_dummies(ins, &dummies_request);
            if (res <= 0)
                return EXIT_FAILURE;
        }
    }

    atomic_store(&state, msg_fin);
    send_request.type = msg_fin;
    send_request.seq = i;
    for(bool first_time = true;;) {
        if (nanoping_send_one(ins, &send_request) < 0)
            return EXIT_FAILURE;
        if (first_time) {
            first_time = false;
            usleep(50000);
        }else{
            usleep(500000);
        }
        if (atomic_load(&state) != msg_fin)
            break;
    }

    if ((res = clock_gettime(CLOCK_MONOTONIC, &finished))) {
        perror("clock_gettime");
        return res;
    }
    timevalsub(&finished, &started, &duration);

    if (pthread_cancel(receive_thread)) {
        perror("pthread_cancel");
        return EXIT_FAILURE;
    }
    if (pthread_join(receive_thread, NULL)) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }
    if (pthread_cancel(process_thread)) {
        perror("pthread_cancel");
        return EXIT_FAILURE;
    }
    if (pthread_join(process_thread, NULL)) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }
    if (pthread_cancel(txs_thread)) {
        perror("pthread_cancel");
        return EXIT_FAILURE;
    }
    if (pthread_join(txs_thread, NULL)) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }

    if (log) {
        fclose(log);
    }
    dump_statistics(ins, &duration, true, pktsize);

    return EXIT_SUCCESS;
}

static int run_server(struct nanoping_instance *ins, char *port, int dummy_pkt)
{
    pthread_t txs_thread = 0;
    bool txs_started = false;
    struct timespec started, finished, duration;
    ssize_t pktsize = 0;

    printf("nanoping server started on port %s.\n", port);
    nanoping_wait_for_receive(ins);
    for (;;) {
        struct nanoping_receive_result receive_result = {0};
        struct nanoping_send_request send_request = {0};
        ssize_t siz;
        int res;

        if (!txs_started) {
            if (pthread_create(&txs_thread, NULL, process_txs_task, ins) < 0) {
                perror("pthread_create");
                return EXIT_FAILURE;
            }
            txs_started = true;
        }
        siz = nanoping_receive_one(ins, &receive_result);
        if (siz < 0)
            return EXIT_FAILURE;

        switch (receive_result.type) {
            case msg_syn:
                if (atomic_load(&state) == msg_none) {
                    atomic_store(&state, msg_pong);
                    send_request.seq = receive_result.seq;
                    send_request.remaddr = receive_result.remaddr;
                    send_request.type = msg_syn_ack;
                    if (nanoping_send_one(ins, &send_request) < 0)
                        return EXIT_FAILURE;
                    printf("Client connected.\n");
                    if ((res = clock_gettime(CLOCK_MONOTONIC, &started))) {
                        perror("clock_gettime");
                        return res;
                    }
                }else{
                    send_request.seq = receive_result.seq;
                    send_request.remaddr = receive_result.remaddr;
                    send_request.type = msg_syn_rst;
                    if (nanoping_send_one(ins, &send_request) < 0)
                        return EXIT_FAILURE;
                    printf("Connection already established, drop new connection request.\n");
                }
                break;
            case msg_fin:
                send_request.seq = receive_result.seq;
                send_request.remaddr = receive_result.remaddr;
                send_request.type = msg_fin_ack;
                if (nanoping_send_one(ins, &send_request) < 0)
                    return EXIT_FAILURE;

                if (atomic_load(&state) != msg_pong) {
                    break;
                }
                if (pthread_cancel(txs_thread)) {
                    perror("pthread_cancel");
                    return EXIT_FAILURE;
                }
                if (pthread_join(txs_thread, NULL)) {
                    perror("pthread_join");
                    return EXIT_FAILURE;
                }
                txs_started = false;
                atomic_store(&state, msg_none);
                printf("Client disconnected.\n");
                if ((res = clock_gettime(CLOCK_MONOTONIC, &finished))) {
                    perror("clock_gettime");
                    return res;
                }
                timevalsub(&finished, &started, &duration);
                dump_statistics(ins, &duration, false, pktsize);
                return EXIT_SUCCESS;
            case msg_ping:
                if (atomic_load(&state) != msg_pong) {
                    fprintf(stderr, "received message (msg_ping) is inconsistent with current state, ignoreing\n");
                    break;
                }
                if (!pktsize)
                    pktsize = siz;

                send_request.seq = receive_result.seq;
                send_request.remaddr = receive_result.remaddr;
                send_request.type = msg_pong;
                if (nanoping_send_one(ins, &send_request) < 0)
                    return EXIT_FAILURE;
                if (dummy_pkt) {
                    struct nanoping_send_dummies_request dummies_request;
                    dummies_request.remaddr = receive_result.remaddr;
                    dummies_request.nmsg = dummy_pkt;

                    res = nanoping_send_dummies(ins, &dummies_request);
                    if (res <= 0)
                        return EXIT_FAILURE;
                }
                break;
            case msg_dummy:
                /* do nothing */
                break;
            default:
                printf("Illigal packet received, ignoreing.\n");
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    struct nanoping_instance *ins = NULL;
    enum nanoping_mode mode = mode_none;
    char *interface = NULL;
    int count = 0;
    int delay = 100;
    char *host = NULL;
    char *port = "10666";
    char *log = NULL;
    bool emulation = false;
    bool ptpmode = false;
    bool silent = false;
    int timeout = 5000000;
    int busy_poll = 0;
    int dummy_pkt = 0;
    int c, res, nargc = argc;

    if (argc >= 2) {
        if (!strcmp(argv[1], "--server")) {
            mode = mode_server;
            nargc--;
        } else if (!strcmp(argv[1], "--client")) {
            mode = mode_client;
            nargc -= 2;
        } else {
            usage();
            return EXIT_FAILURE;
        }
    } else {
	usage();
	return EXIT_FAILURE;
    }
    while ((c = getopt_long(nargc, argv + 1, "i:n:d:p:l:ePst:b:h", longopts, NULL)) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                break;
            case 'n':
                count = atoi(optarg);
                break;
            case 'd':
                delay = atoi(optarg);
                break;
            case 'p':
                port = optarg;
                break;
            case 'l':
                log = optarg;
                break;
            case 'e':
                emulation = true;
                break;
            case 'P':
                ptpmode = true;
                break;
            case 's':
                silent = true;
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'b':
                busy_poll = atoi(optarg);
                break;
            case 'x':
                dummy_pkt = atoi(optarg);
                break;
            case 'h':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }

    if (ptpmode)
        port = "319";
    if (mode == mode_client) {
        host = argv[argc - 1];
        if (!interface || !host) {
            usage();
            return EXIT_FAILURE;
        }
    } else if (mode == mode_server) {
        if (!interface) {
            usage();
            return EXIT_FAILURE;
        }
     }

    pthread_mutex_init(&stats.lock, NULL);
    if ((ins = nanoping_init(interface, port, mode == mode_server ? true: false, emulation, ptpmode, timeout, busy_poll)) == NULL) {
        return EXIT_FAILURE;
    }

    if (mode == mode_client) {
        res = run_client(ins, count, delay, host, port, log, silent, dummy_pkt);
    } else {
        res = run_server(ins, port, dummy_pkt);
    }
    nanoping_finish(ins);
    return res;
}
