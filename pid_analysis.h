#ifndef CS671_PROJECT1_LIBRARY_H
#define CS671_PROJECT1_LIBRARY_H


#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>


#define PROC "/proc" /*Proc file system location */
#define MAX_PID_LOC "/sys/kernel/pid_max" /*Location of the max pid file*/

/**
 * @brief Structure for the analysis data points
 *        required for Assignment 1
 */
typedef struct {
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    time_t start_time;
    long cpu_use_time;
    long cpu_sys_time;
    long res_set_size;
    long txt_mem_size;
    long data_mem_size;
    long shared_mem_size;
    long lib_mem_size;
    long major_faults;
    long minor_faults;
    uid_t real_usr_id;
    uid_t eff_usr_id;
    gid_t real_grp_id;
    gid_t efctv_grp_id;
    char *cmd;
}analysis_struct_t;





#endif