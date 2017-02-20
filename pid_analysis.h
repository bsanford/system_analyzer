#ifndef CS671_PROJECT1_LIBRARY_H
#define CS671_PROJECT1_LIBRARY_H


#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>


#define PROC "/proc" /*Proc file system location */
#define MAX_PID_LOC "/sys/kernel/pid_max" /*Location of the max pid file*/
#define MAX_PID_BYTES 9 /*Assumes 64 bit max plus 1 byte for null terminator*/

/**
 * @brief Structure for the analysis data points
 *        required for Assignment 1
 */
typedef struct {
    char *path;
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    struct timespec start_time;
    struct timespec cpu_use_time;
    struct timespec cpu_sys_time;
    long res_set_size;
    long txt_mem_size;
    unsigned long data_mem_size;
    unsigned long shared_mem_size;
    unsigned long lib_mem_size;
    unsigned long major_faults;
    unsigned long minor_faults;
    uid_t real_usr_id;
    uid_t eff_usr_id;
    gid_t real_grp_id;
    gid_t efctv_grp_id;
    char *cmd;
}analysis_struct_t;







typedef struct {
    int                 pid;
    char                comm[PATH_MAX];
    char                state;
    int                 ppid;
    int                 pgrp;
    int                 session;
    int                 tty_nr;
    int                 tpgid;
    unsigned int        flags;
    unsigned long       minflt;
    unsigned long       cminflt;
    unsigned long       majflt;
    unsigned long       cmajflt;
    unsigned long       utime;
    unsigned long       stime;
    long                cutime;
    long                cstime;
    long                priority;
    long                nice;
    long                num_threads;
    long                itrealvalue;
    unsigned long long  starttime;
    unsigned long       vsize;
    long                rss;
    unsigned long       rsslim;
    unsigned long       startcode;
    unsigned long       endcode;
    unsigned long       startstack;
    unsigned long       kstkesp;
    unsigned long       kstkeip;
    unsigned long       signal;
    unsigned long       blocked;
    unsigned long       sigignore;
    unsigned long       sigcatch;
    unsigned long       wchan;
    unsigned long       nswap;
    unsigned long       cnswap;
    int       exit_signal;
    int                 processor;
    unsigned int        rt_priority;
}status_struct_t;







typedef struct {
    unsigned long long  size;
    unsigned long long  resident;
    unsigned long long  share;
    unsigned long long  text;
    unsigned long long  lib;
    unsigned long long  data;
    unsigned long long  dt;

}statm_struct_t;



#endif
