#include "pid_analysis.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>


#define BUF_SIZE 4096

static pid_t get_maxpids(const char *max_pid_file);
static int process_pids(analysis_struct_t *processes, pid_t max_pids);
static int get_buffer(const char *process_path, char *buffer, size_t buf_size);
int parse_cmd(analysis_struct_t *process, const char *buffer);
static int process_cmdline(analysis_struct_t *process, char *buffer, size_t buf_size);
static int process_mstat(analysis_struct_t *process, char *buffer, size_t buf_size);
static int process_stat(analysis_struct_t *process, char *buffer, size_t buf_size);






/**
 * Main file initializes structures and gets the max pids
 * This will then allocate a buffer for the structure to hold
 * all the pids.
 *
 *
 *
 * Once the pids are initializes the structures will be packed.
 * @return
 */
    int main(void) {

        char *mpid_file;
        pid_t pid_max;
        analysis_struct_t *processes;

        asprintf(&mpid_file, "%s%s", PROC, MAX_PID_LOC); //TODO check pid file

        if ((pid_max = get_maxpids(mpid_file)) == -1) {
            fprintf(stderr, "Error retrieving maximum pids on the system \n");
            exit(EXIT_FAILURE);
        }

        processes = malloc(sizeof(analysis_struct_t) * pid_max); //Allocate the block of memory

        printf("Calling process pids \n");

        if ((process_pids(processes, pid_max)) == -1) {
            fprintf(stderr, "Error processing the pid files \n");
            exit(EXIT_FAILURE); /*Not freeing anything exit does this for us */
        }

        free(mpid_file);
        exit(EXIT_SUCCESS);

    }






/**Function process_pids
 *
 * @brief goes through all the pids directories and finds
 *        the specific files needed to pack the analysis_t structure
 *
 *
 * @return 0 on success -1 on failure
 */
    int process_pids(analysis_struct_t *processes, pid_t max_pids) {

        DIR *proc_dir;
        struct dirent *pid_dir;
        pid_t pidval;
        char *pid_path , buffer[BUF_SIZE];

        if ((proc_dir = opendir(PROC)) == NULL) {
            perror("Open Dir:");
            return (-1);
        }

        while ((pid_dir = readdir(proc_dir)) != NULL) {

            if ((pidval = atoi(pid_dir->d_name)) == 0)//Can get away with this because no process 0
                 continue;


            if ((pidval > max_pids)) {/*sanity check the pid val */
                fprintf(stderr, "Pid value %d is greater than max pids \n", pidval);
                return (-1);
            }

            processes[pidval].pid = pidval;
            asprintf(&(processes[pidval].path), "%s/%s", PROC, pid_dir->d_name);

            if((process_cmdline(&processes[pidval], buffer, BUF_SIZE)) == -1){ //Process cmdline proc file
                fprintf(stderr, "Error in cmdline process \n");
                return (-1);
            }

            if((process_mstat(&processes[pidval], buffer, BUF_SIZE)) == -1){ //Process mstat proc file
                fprintf(stderr, "Error in mstat process \n");
                return (-1);
            }

            if((process_stat(&processes[pidval], buffer, BUF_SIZE))== -1){ //Process stat proce file
                fprintf(stderr, "Error in stat process \n");
                return (-1);
            }

            free(pid_path); //free the memory allocated from the pid path
        }

        return (0);

    }



/**Function process_mstat
 *
 * @param process
 * @param buffer
 * @param buf_size
 * @return
 */

static int process_mstat(analysis_struct_t *process, char *buffer, size_t buf_size){
    char *cmd_path;

    asprintf(&cmd_path, "%s/%s", process->path, "statm");

    statm_struct_t *mstat = malloc(sizeof(status_struct_t));

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        free(mstat);
        free(cmd_path);
        return (-1);
    }


    if ((sscanf(buffer,"%llu%llu%llu%llu%llu%llu%llu",&(mstat->size), &(mstat->resident), &(mstat->share),
                                                      &(mstat->text),  &(mstat->lib),
                                                      &(mstat->data), &(mstat->dt))) == -1){
        perror("Couldn't scanf the mstat buffer :");
        free(mstat);
        free(cmd_path);
        return (-1);
    }

    free(mstat);
    free(cmd_path);
     return(0);
}







/**Function process_stat
 * @brief high level function for processing the stat file and packing
 *        the analysis_struct_t structure.
 *
 * @param process
 * @param buffer
 * @param buf_size
 * @return returns 0 on success -1 on error
 */
static int process_stat(analysis_struct_t *process, char *buffer, size_t buf_size){
     char *cmd_path;
     char *strt;
     char *end;
    status_struct_t *stat = malloc(sizeof(status_struct_t));
     asprintf(&cmd_path, "%s/%s", process->path, "stat");
    
    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        free(cmd_path);
        return (-1);
    }

   if((sscanf(buffer, "%d", &stat->pid)) == -1){
	fprintf(stderr, "Couldn't parse stat pid info from buffer \n");
    free(cmd_path);
	return (-1);	
   }

   /*I used part of this to parse the comm section -> https://www.redhat.com/archives/axp-list/2001-January/msg00355.html*/
   strt = strchr (buffer, '(') + 1;
   end  = strchr (buffer, ')');
   strncpy (stat->comm, strt, end-strt);

   stat->comm[end-strt] = '\0';

   sscanf(end + 2,"%c%d%d%d%d%d%u%lu%lu%lu%lu%lu%lu%ld%ld%ld"
                       "%ld%ld%ld%llu%lu%ld%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%d%d%u",
                       &(stat->state),&(stat->ppid), &(stat->pgrp),&(stat->session), (&stat->tty_nr),
                       &(stat->tpgid), &(stat->flags), &(stat->minflt),&(stat->cminflt), &(stat->majflt),
                       &(stat->cmajflt),&(stat->utime), &(stat->stime), &(stat->cutime),&(stat->cstime),
                       &(stat->priority), &(stat->nice), &(stat->num_threads), &(stat->itrealvalue),
                       &(stat->starttime),&(stat->vsize),&(stat->rss), &(stat->rsslim),
                       &(stat->startcode), &(stat->endcode),&(stat->startstack), &(stat->kstkesp),
                       &(stat->kstkeip), &(stat->signal), &(stat->blocked), &(stat->sigignore),
                       &(stat->sigcatch), &(stat->wchan), &(stat->nswap), &(stat->cnswap), &(stat->exit_signal),
                       &(stat->processor),&(stat->rt_priority));


    /*TODO Should refactor to have this in its own function*/
    process->ppid = stat->ppid;
    process->pgid = stat->pgrp;
    process->start_time.tv_sec   = (stat->starttime / sysconf(_SC_CLK_TCK));
    process->cpu_sys_time.tv_sec = (stat->stime / sysconf(_SC_CLK_TCK));
    process->cpu_use_time.tv_sec = (stat->utime / sysconf(_SC_CLK_TCK));
    process->major_faults = stat->majflt;
    process->minor_faults = stat->minflt;



   free(cmd_path);
   free(stat);   
    return(0);
}



/**Function process status
 *
 * Processes the status file to get the UUIDs of the process
 *
 */

void process_status(void){

}









/** Function process_cmdline
 *
 * @brief high level function that gets a buffer with the contents of the
 *        the /proc/<ID>/cmdline file and prcocess the contents of the buffer
 *        into the analysis_struct_t. In this case it just copies the buffer;
 *
 * @param process
 * @param buffer
 * @param buf_size
 * @return -1 errror 0 success
 */
static int process_cmdline(analysis_struct_t *process, char *buffer, size_t buf_size){

    char *cmd_path;

    asprintf(&cmd_path, "%s/%s", process->path, "cmdline"); //TODO add check

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        return (1);
    }

    if((parse_cmd(process, buffer)) == -1){
        fprintf(stderr, "Couldn't parse the command line file \n");
        return (-1);
    }
    return (0);
}








/**
 * @brief Function get_maxpids opens and attempts
 *        to read and parse the pid_max file in
 *        proc
 * @param max_pids_file - the full path to the /proc max pid file
 * @return returns the amount of pids in the file
 */
    static pid_t get_maxpids(const char *max_pid_file) {

        FILE *pid_file;
        char buffer[MAX_PID_BYTES];
        if ((pid_file = (fopen(max_pid_file, "r"))) == NULL) {
            perror("Couldn't open max pid file : ");
            return (-1);
        }

        if ((fgets(buffer, MAX_PID_BYTES, pid_file) == NULL)) {
            perror("Couldn't read pid_file: ");
            return (-1);
        }

        fclose(pid_file);

        return atoi(buffer);
    }









/**Function get_cmd
 *
 * @param process - pointer to the struct that maps to the process id
 * @param process_path process path - path to the process that we are working with
 * @return returns 0 on success -1 on failure
 */
    static int get_buffer(const char *process_path, char *buffer, size_t buf_size) {

        FILE *file;

        memset(buffer, '\0', buf_size);

        if ((file = fopen(process_path, "r")) == NULL) {
            perror("Error opening cmdfile :");
             return (-1);
        }

        fgets(buffer, buf_size, file);

        if ((fclose(file)) == EOF) {
            perror("Error closing command line file :");
            return (-1);
        }

        return (0);
    }









int parse_cmd(analysis_struct_t *process, const char *buffer){
    int lnth;

    lnth = strlen(buffer);
    process->cmd = malloc(lnth + 1);

    if (process->cmd == NULL) {
        fprintf(stderr, "Couldn't allocate memory for cmd elment in struct");
        return (-1);
    }

    strncpy((process->cmd), buffer, (lnth + 1));
    return (0);
}







