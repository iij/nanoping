#ifndef NANOPING_H
#define NANOPING_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <netinet/in.h>

struct nanoping_timeval {
    int64_t tv_sec;
    int64_t tv_nsec;
};

#define logprintf(log, ...) if (log) { fprintf(log, __VA_ARGS__); fflush(log); }

#define timevaladd(tvp, uvp, vvp) \
    do { \
        (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec; \
        (vvp)->tv_nsec = (tvp)->tv_nsec + (uvp)->tv_nsec; \
        if ((vvp)->tv_nsec >= 1000000000) { \
            (vvp)->tv_sec++; \
            (vvp)->tv_nsec -= 1000000000; \
        } \
    } while (0)

#define timevalsub(tvp, uvp, vvp) \
    do { \
        assert(!timevalcmp(tvp, uvp, <)); \
        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec; \
        (vvp)->tv_nsec = (tvp)->tv_nsec - (uvp)->tv_nsec; \
        if ((vvp)->tv_nsec < 0) { \
            (vvp)->tv_sec--; \
            (vvp)->tv_nsec += 1000000000; \
        } \
    } while (0)

#define timevalcmp(tvp, uvp, cmp) \
    (((tvp)->tv_sec == (uvp)->tv_sec) ? \
    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) : \
    ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define timevaldiv2(tvp, x) \
    do { \
        (tvp)->tv_sec = (tvp)->tv_sec / x; \
        (tvp)->tv_nsec = (tvp)->tv_nsec / x; \
    } while(0)

TAILQ_HEAD(nanoping_rx_record_head, nanoping_rx_record);
TAILQ_HEAD(nanoping_txs_record_head, nanoping_txs_record);
struct nanoping_instance {
    int fd;
    int nots_fd;
    struct sockaddr_in myaddr;
    struct nanoping_rx_record_head rx_head;
    struct nanoping_rx_record_head rx4proc_head;
    struct nanoping_rx_record_head rx4tx_head;
    struct nanoping_txs_record_head txs_head;
    struct nanoping_txs_record_head txs4proc_head;
    struct nanoping_txs_record_head rem_txs_head;
    pthread_mutex_t rx_lock;
    pthread_mutex_t rx4proc_lock;
    pthread_mutex_t rx4tx_lock;
    pthread_mutex_t txs_lock;
    pthread_mutex_t txs4proc_lock;
    pthread_mutex_t rem_txs_lock;
    bool server;
    bool emulation;
    bool ptpmode;
    int emul_fds[2];
    unsigned long pkt_received;
    unsigned long pkt_transmitted;
    unsigned long rxs_collected;
    unsigned long txs_collected;
    unsigned long rem_rxs_collected;
    unsigned long rem_txs_collected;
    unsigned long rx_prev_rxs_found;
    unsigned long rx_prev_txs_found;
    unsigned long tx_prev_rxs_found;
    unsigned long tx_prev_txs_found;
    unsigned long tx_prev_txs_too_late;
    uint64_t sent_seq;
};

enum nanoping_msg_type {
    msg_none = 0,
    msg_syn,
    msg_syn_ack,
    msg_syn_rst,
    msg_ping,
    msg_pong,
    msg_fin,
    msg_fin_ack,
    msg_dummy,
};

struct nanoping_send_request {
    enum nanoping_msg_type type;
    uint64_t seq;
    struct sockaddr_in remaddr;
};

struct nanoping_send_dummies_request {
    struct sockaddr_in remaddr;
    int nmsg;
};

enum nanoping_receive_error {
    rxerr_none = 0x0,
    rxerr_rxs_failed = 0x1,
    rxerr_rem_rxs_failed = 0x2,
    rxerr_rem_txs_failed = 0x4,
    rxerr_rx_dropped = 0x8,
    rxerr_tx_dropped = 0x10
};

struct nanoping_receive_result {
    enum nanoping_msg_type type;
    uint64_t seq;
    struct sockaddr_in remaddr;
};

struct nanoping_process_result {
    uint64_t seq;
    struct nanoping_timeval t0, t1, t2, t3;
    int num_txs;
    enum nanoping_receive_error error;
};


struct nanoping_instance *nanoping_init(char *interface, char *port, bool server, bool emulation, bool ptpmode, int timeout, int busy_poll);
int nanoping_process_one(struct nanoping_instance *ins,
    struct nanoping_process_result *result);
int nanoping_wait_for_receive(struct nanoping_instance *ins);
ssize_t nanoping_receive_one(struct nanoping_instance *ins,
    struct nanoping_receive_result *result);
ssize_t nanoping_send_one(struct nanoping_instance *ins,
    struct nanoping_send_request *request);
int nanoping_send_dummies(struct nanoping_instance *ins,
    struct nanoping_send_dummies_request *request);
int nanoping_txs_one(struct nanoping_instance *ins);
void nanoping_reset_state(struct nanoping_instance *ins);
void nanoping_finish(struct nanoping_instance *ins);

#endif
