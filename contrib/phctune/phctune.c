#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <sys/timex.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/ptp_clock.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include "nanoping.h"

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd) ((~(clockid_t) (fd) << 3) | CLOCKFD)
#define CLOCKID_TO_FD(clk) ((unsigned int) ~((clk) >> 3))
#define PHCDEV_LEN 32

static struct option longopts[] = {
    {"interface", required_argument, NULL, 'i'},
    {"subinterface", required_argument, NULL, 'I'},
    {"sleep", required_argument, NULL, 's'},
    {"log",     required_argument,  NULL,   'l'},
    {"help",    no_argument,        NULL,   'h'},
    {0,         0,                  0,  0}
};

static void usage(void)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  phctune --interface [nic] --subinterface [nic] --sleep [sec] --log [log]\n");
}

static inline int clock_adjtime(clockid_t id, struct timex *tx)
{
    return syscall(__NR_clock_adjtime, id, tx);
}

static int iface_to_phcidx(const char *name)
{
    struct ethtool_ts_info tsi = {0};
    struct ifreq ifr = {{'\0'}, };
    int fd;
    int res;

    tsi.cmd = ETHTOOL_GET_TS_INFO;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_data = (char *)&tsi;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }
    res = ioctl(fd, SIOCETHTOOL, &ifr);
    if (res < 0) {
        perror("ioctl");
        return res;
    }
    close(fd);
    if (tsi.phc_index < 0) {
        fprintf(stderr, "Cannot find phcdev of %s\n", name);
        return -1;
    }
    return tsi.phc_index;
}

struct clkdiff_result {
    struct timespec host_start, host_end, host_elapsed;
    struct timespec phc_start[2], phc_end[2], phc_elapsed[2];
    int64_t phc_diff[2];
};

static inline int timespecsub_int64(struct timespec *tvp, struct timespec *uvp, int64_t *vvp)
{
    bool negative = false;
    struct timespec vv;
    if (timevalcmp(tvp, uvp, <)) {
        negative = true;
        timevalsub(uvp, tvp, &vv);
    } else
        timevalsub(tvp, uvp, &vv);
    if (vv.tv_sec > 0)
        return -1;
    if (negative)
        *vvp = -vv.tv_nsec;
    else
        *vvp = vv.tv_nsec;
    return 0;
}

static inline int adjust_ppb(clockid_t clkid, double ppb)
{
    struct timex tx = {.modes = ADJ_FREQUENCY, .freq = (long)(ppb * 65.536)};
    return clock_adjtime(clkid, &tx);
}

static inline int validate_clockid(clockid_t clkid)
{
    struct ptp_clock_caps caps;
    return ioctl(CLOCKID_TO_FD(clkid), PTP_CLOCK_GETCAPS, &caps);
}

static int measure_clkdiff(clockid_t clkid[2], double ppb, int nsleep, bool subinterface, struct clkdiff_result *result)
{
    int res;

    assert(result);

    res = adjust_ppb(clkid[0], ppb);
    if (res) {
        perror("adjust_ppb");
        return res;
    }
    if (subinterface) {
        res = adjust_ppb(clkid[1], ppb);
        if (res) {
            perror("adjust_ppb");
            return res;
        }
    }

    res = clock_gettime(CLOCK_REALTIME, &result->host_start);
    if (res) {
        perror("clock_gettime");
        return res;
    }
    res = clock_gettime(clkid[0], &result->phc_start[0]);
    if (res) {
        perror("clock_gettime");
        return res;
    }
    if (subinterface) {
        res = clock_gettime(clkid[1], &result->phc_start[1]);
        if (res) {
            perror("clock_gettime");
            return res;
        }
    }

    sleep(nsleep);

    res = clock_gettime(CLOCK_REALTIME, &result->host_end);
    if (res) {
        perror("clock_gettime");
        return res;
    }

    res = clock_gettime(clkid[0], &result->phc_end[0]);
    if (res) {
        perror("clock_gettime");
        return res;
    }

    if (subinterface) {
        res = clock_gettime(clkid[1], &result->phc_end[1]);
        if (res) {
            perror("clock_gettime");
            return res;
        }
    }

    timevalsub(&result->host_end, &result->host_start, &result->host_elapsed);
    timevalsub(&result->phc_end[0], &result->phc_start[0], &result->phc_elapsed[0]);
    res = timespecsub_int64(&result->host_elapsed, &result->phc_elapsed[0], &result->phc_diff[0]);
    if (res) {
        fprintf(stderr, "phc[0] diff is too large (>1sec)\n");
        return -1;
    }
    if (subinterface) {
        timevalsub(&result->phc_end[1], &result->phc_start[1], &result->phc_elapsed[1]);
        res = timespecsub_int64(&result->host_elapsed, &result->phc_elapsed[1], &result->phc_diff[1]);
        if (res) {
            fprintf(stderr, "phc[1] diff is too large (>1sec)\n");
            return -1;
        }
    }

    return 0;
}

static void print_result(struct clkdiff_result *result, double ppb, bool subinterface, FILE *log)
{
    printf("  host start:%ld.%09ld end:%ld.%09ld elapsed:%ld.%09ld\n",
            result->host_start.tv_sec, result->host_start.tv_nsec, result->host_end.tv_sec, result->host_end.tv_nsec, result->host_elapsed.tv_sec, result->host_elapsed.tv_nsec);
    printf("  phc[0] start:%ld.%09ld end:%ld.%09ld elapsed:%ld.%09ld diff:%09ld\n",
            result->phc_start[0].tv_sec, result->phc_start[0].tv_nsec, result->phc_end[0].tv_sec, result->phc_end[0].tv_nsec, result->phc_elapsed[0].tv_sec, result->phc_elapsed[0].tv_nsec, result->phc_diff[0]);
    if (subinterface) {
        printf("  phc[1] start:%ld.%09ld end:%ld.%09ld elapsed:%ld.%09ld diff:%09ld\n",
                result->phc_start[1].tv_sec, result->phc_start[1].tv_nsec, result->phc_end[1].tv_sec, result->phc_end[1].tv_nsec, result->phc_elapsed[1].tv_sec, result->phc_elapsed[1].tv_nsec, result->phc_diff[1]);
    }

    if (!subinterface) {
        logprintf(log, "%f,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%09ld\n",
                ppb, result->host_start.tv_sec, result->host_start.tv_nsec, result->host_end.tv_sec, result->host_end.tv_nsec, result->host_elapsed.tv_sec, result->host_elapsed.tv_nsec, result->phc_start[0].tv_sec, result->phc_start[0].tv_nsec, result->phc_end[0].tv_sec, result->phc_end[0].tv_nsec, result->phc_elapsed[0].tv_sec, result->phc_elapsed[0].tv_nsec, result->phc_diff[0]);
    }else{
        logprintf(log, "%f,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%09ld,%ld.%09ld,%ld.%09ld,%ld.%09ld,%09ld\n",
                ppb, result->host_start.tv_sec, result->host_start.tv_nsec, result->host_end.tv_sec, result->host_end.tv_nsec, result->host_elapsed.tv_sec, result->host_elapsed.tv_nsec, result->phc_start[0].tv_sec, result->phc_start[0].tv_nsec, result->phc_end[0].tv_sec, result->phc_end[0].tv_nsec, result->phc_elapsed[0].tv_sec, result->phc_elapsed[0].tv_nsec, result->phc_diff[0], result->phc_start[1].tv_sec, result->phc_start[1].tv_nsec, result->phc_end[1].tv_sec, result->phc_end[1].tv_nsec, result->phc_elapsed[1].tv_sec, result->phc_elapsed[1].tv_nsec, result->phc_diff[1]);
    }
}

int main(int argc, char **argv)
{
    char *ifname = NULL;
    char *subifname = NULL;
    bool subinterface = false;
    clockid_t clkid[2];
    int fd[2], res, c, phcidx[2];
    static const struct timespec zero_ts = {0};
    struct clkdiff_result result = {{0}};
    char phcdev[2][PHCDEV_LEN];
    int nsleep = 100;
    int64_t best_diff = INT64_MAX;
    double best_ppb = 0, ppb = 0;
    double middle_ppb = 0;
    double ppb_width = 500;
    double ppb_step = 100;
    char *logpath = NULL;
    FILE *log = NULL;

    while ((c = getopt_long(argc, argv, "i:I:s:h", longopts, NULL)) != -1) {
        switch (c) {
            case 'i':
                ifname = optarg;
                break;
            case 'I':
                subifname = optarg;
                subinterface = true;
                break;
            case 's':
                nsleep = atoi(optarg);
                break;
            case 'l':
                logpath = optarg;
                break;
            case 'h':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }

    if (!ifname) {
        usage();
        return EXIT_FAILURE;
    }

    if (logpath) {
        if ((log = fopen(logpath, "w")) == NULL) {
            perror("fopen");
            return EXIT_FAILURE;
        }
    }

    logprintf(log, "ppb,host_start,host_end,host_elapsed,phc1_start,phc1_end,phc1_elapsed,phc1_diff,phc1_start,phc1_end,phc1_elapsed,phc1_diff\n");

    phcidx[0] = iface_to_phcidx(ifname);
    if (phcidx[0] < 0)
        return EXIT_FAILURE;
    res = snprintf(phcdev[0], PHCDEV_LEN-1, "/dev/ptp%d", phcidx[0]);
    if (res < 0) {
        perror("snprintf");
        return EXIT_FAILURE;
    }

    if (subinterface) {
        phcidx[1] = iface_to_phcidx(subifname);
        if (phcidx[1] < 0)
            return EXIT_FAILURE;
        res = snprintf(phcdev[1], PHCDEV_LEN-1, "/dev/ptp%d", phcidx[1]);
        if (res < 0) {
            perror("snprintf");
            return EXIT_FAILURE;
        }
    }

    printf("NIC0:%s PHC0:%s sleep:%d\n", ifname, phcdev[0], nsleep);
    if (subinterface)
        printf("NIC1:%s PHC1:%s\n", subifname, phcdev[1]);
    printf("\n");

    fd[0] = open(phcdev[0], O_RDWR);
    if (fd[0] < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    clkid[0] = FD_TO_CLOCKID(fd[0]);
    res = validate_clockid(clkid[0]);
    if (res) {
        fprintf(stderr, "could not get correct clockid\n");
        return EXIT_FAILURE;
    }
    if (subinterface) {
        fd[1] = open(phcdev[1], O_RDWR);
        if (fd[1] < 0) {
            perror("open");
            return EXIT_FAILURE;
        }
        clkid[1] = FD_TO_CLOCKID(fd[1]);
        res = validate_clockid(clkid[1]);
        if (res) {
            fprintf(stderr, "could not get correct clockid\n");
            return EXIT_FAILURE;
        }
    }

    // reset phc clocks to 0
    res = clock_settime(clkid[0], &zero_ts);
    if (res) {
        perror("clock_settime");
        return -1;
    }
    if (subinterface) {
        res = clock_settime(clkid[1], &zero_ts);
        if (res) {
            perror("clock_settime");
            return -1;
        }
    }

    printf("[ppb %f]\n", ppb);
    res = measure_clkdiff(clkid, ppb, nsleep, subinterface, &result);
    print_result(&result, ppb, subinterface, log);
    if (res)
        return EXIT_FAILURE;

    best_ppb = middle_ppb = result.phc_diff[0] / nsleep;
    best_diff = result.phc_diff[0];

    printf("  best ppb:%f\n", best_ppb);
    printf("  middle ppb:%f\n", middle_ppb);
    printf("\n");

    for (;;) {
        int not_updated = 0;
        printf("ppb_step:%f ppb_width:%f middle_ppb:%f\n\n", ppb_step, ppb_width, middle_ppb);
        for (ppb = middle_ppb - ppb_width; ppb < middle_ppb + ppb_width; ppb += ppb_step) {
            struct clkdiff_result result = {{0}};
            printf("[ppb %f]\n", ppb);
            res = measure_clkdiff(clkid, ppb, nsleep, subinterface, &result);
            print_result(&result, ppb, subinterface, log);
            if (res)
                return EXIT_FAILURE;

            if (labs(best_diff) > labs(result.phc_diff[0])) {
                best_diff = result.phc_diff[0];
                best_ppb = ppb;
                printf("best ppb:%f\n", best_ppb);
            } else if (ppb > middle_ppb) {
                not_updated++;
            }
            printf("\n");
            if (not_updated > 2)
                break;
        }
        if (ppb_step < 0.1)
            break;
        ppb_step /= 10;
        ppb_width /= 10;
        middle_ppb = best_ppb;
        printf("middle ppb:%f\n", middle_ppb);
    }

    printf("best_ppb:%f\n", best_ppb);

    res = adjust_ppb(clkid[0], best_ppb);
    if (res) {
        perror("adjust_ppb");
        return EXIT_FAILURE;
    }
    if (subinterface) {
        res = adjust_ppb(clkid[1], ppb);
        if (res) {
            perror("adjust_ppb");
            return EXIT_FAILURE;
        }
    }

    close(fd[0]);
    if (subinterface)
        close(fd[1]);
    if (log)
        fclose(log);
    return EXIT_SUCCESS;
}
