#include "pid_analysis.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>


#define MAX_PID_LOC "/sys/kernel/pid_max"
#define MAX_PID_BYTES 9 /*Assumes 64 bit max plus 1 byte for null terminator*/



static pid_t get_maxpids(const char *max_pid_file);
static int process_pids(analysis_struct_t *processes, pid_t max_pids);
static int get_cmd(analysis_struct_t *process, const char *process_path);






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
        char *pid_path;

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

            asprintf(&pid_path, "%s/%s", PROC, pid_dir->d_name); //TODO add check


            if ((get_cmd(&processes[pidval], pid_path)) == -1) {
                fprintf(stderr, "Couldn't define the cmd_line parameter \n");
                return (1);
            }

            processes[pidval].pid = pidval;
            printf("Process id %d , proces path %s, cmd = %s \n", processes[pidval].pid, pid_path,
                   processes[pidval].cmd);
            free(pid_path); //free the memory allocated from the pid path
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
    static int get_cmd(analysis_struct_t *process, const char *process_path) {

        FILE *cmd_file;
        char *cmd_file_path;
        char buffer[4096];
        size_t lnth;


        memset(buffer, '\0', sizeof(buffer));

        if ((asprintf(&cmd_file_path, "%s/cmdline", process_path)) == -1)
            fprintf(stderr, "ERROR - Couldn't allocate cmdline file path \n");

        if ((cmd_file = fopen(cmd_file_path, "r")) == NULL) {
            perror("Error opening cmdfile :");
            free(cmd_file_path);
            return (-1);
        }


        fgets(buffer, sizeof(buffer), cmd_file);

        if ((fclose(cmd_file)) == EOF) {
            perror("Error closing command line file :");
            return (-1);
        }


        lnth = strlen(buffer);
        process->cmd = malloc(lnth + 1);

        if (process->cmd == NULL) {
            fprintf(stderr, "Couldn't allocate memory for cmd elment in struct");
            return (-1);
        }

        strncpy((process->cmd), buffer, (lnth + 1));
        free(cmd_file_path);
        return (0);
    }





/**Function get pstat
 *
 *@brief parses the pstat file located at
 *
 * @param process
 * @param pid_path
 * @return
 */
int get_pstat(analysis_struct_t *process, const char *pid_path){

    return (0);

}


/**Fucntion get_pstatm
 * @brief parses the statm file passed in via pid_path
 *
 * @param pid_path
 * @return
 */
int get_pstatm(analysis_struct_t *process, const char *pid_path){
    return (0);
}



