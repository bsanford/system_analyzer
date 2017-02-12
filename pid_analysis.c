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

            if ((pidval = atoi(pid_dir->d_name)) == 0)
                 continue;


            if ((pidval > max_pids)) {/*sanity check the pid val */
                fprintf(stderr, "Pid value %d is greater than max pids \n", pidval);
                return (-1);
            }

            processes[pidval].pid = pidval;

            asprintf(&(processes[pidval].path), "%s/%s", PROC, pid_dir->d_name); //Set up the proc path for pid

            process_cmdline(&processes[pidval], buffer, BUF_SIZE); // Call process cmdlin

            process_mstat(&processes[pidval], buffer, BUF_SIZE);

            process_stat(&processes[pidval], buffer, BUF_SIZE);

            printf("Process id %d , proces path %s, cmd = %s \n", processes[pidval].pid, processes[pidval].path,
                   processes[pidval].cmd);

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

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        return (-1);
    }

    printf("stat m buffer =%s \n", buffer);
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
      asprintf(&cmd_path, "%s/%s", process->path, "stat");

    if ((get_buffer(cmd_path, buffer, buf_size)) == -1) {
        fprintf(stderr, "Couldn't define the cmd_line parameter \n");
        return (-1);
    }

    printf("stat  buffer =%s \n", buffer);
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






char *get_stat(char *stat_buf, int stat_loc, int stat_buf_size){

}


