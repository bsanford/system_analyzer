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
void print_analysis(analysis_struct_t *processes, size_t buf_size);
static int  process_status(analysis_struct_t *process, char *buffer, size_t buf_size);






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
    int main(void){

        char *mpid_file;
        pid_t pid_max;
        analysis_struct_t *processes;

       if((asprintf(&mpid_file, "%s%s", PROC, MAX_PID_LOC)) == -1)
            exit(EXIT_FAILURE);

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
        char buffer[BUF_SIZE];

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
            if((asprintf(&(processes[pidval].path), "%s/%s", PROC, pid_dir->d_name)) == -1){
                fprintf(stderr, "Error couldn't generate proc path \n");
                return (-1);
            }

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

            if((process_status(&processes[pidval], buffer, BUF_SIZE))== -1){ //Process stat proce file
                fprintf(stderr, "Error in stat process \n");
                return (-1);
            }


        }

         print_analysis(processes, max_pids);
        return (0);

    }







/**Function process_mstat
 *
 * @brief processes and parses the mstat file, puts all data elements of mstat into mstat structure, then maps
 *        to the analysis_t structure. Design wise would be better to just parse mstat into a structure and then have a
 *        seperate mapping function so it could be more re usable but since this was academic I lumped it all together.
 *
 * @param process - the current pid being processed
 * @param buffer - buffer to hold contents of mstat
 * @param buf_size - size of the buffer
 * @return 0 on success -1 on failure
 */

static int process_mstat(analysis_struct_t *process, char *buffer, size_t buf_size){
    char *cmd_path;
    int page_size;

    if((asprintf(&cmd_path, "%s/%s", process->path, "statm")) == -1){
        fprintf(stderr, "Couldn't generate mstat path");
        return (-1);
    }

    statm_struct_t *mstat = malloc(sizeof(status_struct_t));

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        free(mstat);
        free(cmd_path);
        return (-1);
    }

    /*Each value in mstat is the count of pages, so page size in bytes * number of pages = total number of bytes*/
    page_size = getpagesize();


    if ((sscanf(buffer,"%llu%llu%llu%llu%llu%llu%llu",&(mstat->size), &(mstat->resident), &(mstat->share),
                                                      &(mstat->text),  &(mstat->lib),
                                                      &(mstat->data), &(mstat->dt))) == -1){
        perror("Couldn't scanf the mstat buffer :");
        free(mstat);
        free(cmd_path);
        return (-1);
    }
    process->res_set_size = mstat->resident * page_size;
    process->txt_mem_size = mstat->share * page_size;
    process->lib_mem_size = mstat->lib * page_size;
    process->shared_mem_size = mstat->share * page_size;

    free(mstat);
    free(cmd_path);
     return(0);
}








/**Function print_analysis
 *
 * Loops over the array of pointers to processes and printfs CSV formatted output of packed data
 *
 * @param processes the start address to the array of analysis_t pointers
 * @param buf_size how many pointers there are
 */

void print_analysis(analysis_struct_t *processes, size_t buf_size){

    size_t index;
    printf("PID,PPID,PGID,START_TIME,CPU_USE_TIME,CPU_SYS_TIME,RES_SET_SIZE,TXT_MEM_SIZE, DATA_MEM_SIZE,"
                   "LIB_MEM_SIZE,MAJOR_FAULTS,MINOR_FAULTS,REAL_USR_ID,EFF_USR_ID,REAL_GRP_ID,EFCTV_GROUP_ID,"
                   "CMD \n");
    for(index = 1; index <= buf_size; index++) {
        if (processes[index].pid == 0)
            continue;

        printf("%d,%d,%d,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%d,%d,%d,%d,%s \n",
               processes[index].pid, processes[index].ppid, processes[index].pgid,
               processes[index].start_time.tv_sec, processes[index].cpu_use_time.tv_sec,
               processes[index].cpu_sys_time.tv_sec,processes[index].res_set_size,processes[index].txt_mem_size,
               processes[index].data_mem_size,processes[index].lib_mem_size, processes[index].major_faults,
               processes[index].minor_faults,processes[index].real_usr_id,processes[index].eff_usr_id,
               processes[index].real_grp_id,processes[index].efctv_grp_id,processes[index].cmd);
    }


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

    if((asprintf(&cmd_path, "%s/%s", process->path, "stat")) == -1){
        fprintf(stderr, "Couldn't generate stat path \n");
        return (-1);
    }
    
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




static int get_status_line(const char *process_path, char *buffer, size_t buf_size, const char *srch){


    FILE *file;
    memset(buffer, '\0', buf_size);

    if ((file = fopen(process_path, "r")) == NULL) {
        perror("Error opening cmdfile :");
        return (-1);
    }


    while (fgets(buffer, buf_size, file) != NULL) {
        if ((strstr(buffer, srch)) != NULL) {
            fclose(file);
            return (0);
        }
    }
  fclose(file);

   fprintf(stderr, "File does not contain search string \n");
  return (-1);

}








/**Process_Staus
 * @brief process status goes through the status file looking specifically for
 *        UID and GID data. When the given status field is found in the file it
 *        then parses the fields for the required GID and UID data
 *
 * @param process
 * @param buffer
 * @param buf_size
 * @return -1 on error 0 on success
 */

static int  process_status(analysis_struct_t *process, char *buffer, size_t buf_size){
    char *cmd_path;

    if((asprintf(&cmd_path, "%s/%s", process->path, "status")) == -1){
        fprintf(stderr, "Couldn't generate cmd line path \n");
        return (-1);
    }

    if((get_status_line(cmd_path, buffer, buf_size, "Uid")) == -1){
        fprintf(stderr, "Uid not found in STATUS file erroring \n");
        return (-1);
    }

    if((sscanf(buffer, "Uid: %d %d", &(process->real_usr_id), &(process->eff_usr_id))) == -1){
        fprintf(stderr , "Couldn't parse UID buffer \n");
        return (-1);
    }


    if((get_status_line(cmd_path, buffer, buf_size, "Gid")) == -1){
        fprintf(stderr, "Gid not found in STATUS file erroring \n");
        return (-1);
    }

    if((sscanf(buffer, "Gid: %d %d", &(process->real_grp_id), &(process->efctv_grp_id))) == -1){
        fprintf(stderr , "Couldn't parse GID buffer \n");
        return (-1);
    }

    return(0);
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

    if((asprintf(&cmd_path, "%s/%s", process->path, "cmdline")) == -1){
        fprintf(stderr, "Couldn't generate cmd line path \n");
        return (-1);
    }

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        free(cmd_path);
        return (1);
    }

    if((parse_cmd(process, buffer)) == -1){
        fprintf(stderr, "Couldn't parse the command line file \n");
        free(cmd_path);
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
 * @brief prepares the buffer for use, since this is a syncronis process there is only one char buffer that is
 *        shared between all the parsed files under /proc
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








/**Function parse_cmd
 *
 * @param process
 * @param buffer
 * @return
 */
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







