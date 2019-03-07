#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// NEW CODE
// Needed by process.c to return errors for child processes
#define ERROR -1    /* Error code is -1 for any system calls that can fail */
// Needed by process.c to close files before termination
#define CLOSE_ALL -1              /* pass -1 to close all files opened by process */
/* Child Process Setup */
#define NOT_LOADED = 0
#define LOAD_SUCCESS = 1
#define LOAD_FAIL = -1
//Child Process Structure
struct child_process {
  int pid;    //parent id
  int load;   //load status
  bool wait;  //whether the process is waiting
  bool exit;  //whether the process has exited
  int status; //exit status inherited from parent
  struct lock wait_lock;  //lock for waiting
  struct list_elem elem;  //list_elem for iteration
};
struct child_process* get_child_process(int pid);
void remove_child_process(int pid);
/***********************/
void process_close_file(int fd);  /* passes the file number of the file to be closed */ 
// END NEW CODE

void syscall_init (void);

#endif /* userprog/syscall.h */
