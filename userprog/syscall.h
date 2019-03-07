#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// NEW CODE
// Needed by process.c to close files before termination
#define CLOSE_ALL -1              /* pass -1 to close all files opened by process */
void process_close_file(int fd);  /* passes the file number of the file to be closed */ 
// END NEW CODE

void syscall_init (void);

#endif /* userprog/syscall.h */
