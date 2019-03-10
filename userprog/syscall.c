#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// NEW CODE
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define ARG_MAX 4		/* Maximum number of arguments to pass to a system call, including the type of call */
#define VADDR_BOTTOM ((void *) 0x08048000) // bottom of the v address space
struct lock file_lock;  /* Lock that prevents multiple files in same file directory from being manipulated at once. */
// Struct to hold a file, its file descriptor and a list_elem for iteration
struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};
// END NEW CODE

static void syscall_handler (struct intr_frame *);
// NEW CODE
int user_to_kernel_ptr(const void *vaddr);
int process_add_file(struct file *f);
struct file* process_get_file(int fd);
void process_close_file(int fd);
bool is_valid_buffer(void* buffer, unsigned size);
// END NEW CODE

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* OLD CODE
  printf ("system call!\n");
  thread_exit ();
     END OLD CODE */

  // NEW CODE
  int i, arg[ARG_MAX]; //declare variables used by handler
  if(!is_valid_ptr(((const void*) f->esp))) // exit with error if not valid pointer
	  exit(-1);
  for (i = 0; i < ARG_MAX; i++)
  {
	if(!is_valid_ptr((const void*)((int *) f->esp+i))) // checking each arg for valid ptr
		exit(-1); // exit with error if not
    arg[i] = *((int *)f->esp + i);  //add arguments to the arg array
  }
  switch (arg[0])   //first arg determines the call to make
  {
    case SYS_HALT:
    {
      halt();   //shutdown
      break;
    }
    case SYS_EXIT:
    {
      exit(arg[1]);   //pass the status to exit
      break;
    }
    case SYS_EXEC:
    {
      arg[1] = user_to_kernel_ptr((const void *)arg[1]);           //converts usr ptr to kernel ptr for name of executable
      f->eax = exec((const char *)arg[1]);                         //passes the name of the executable into exec()
      break;
    }
    case SYS_WAIT:
    {
      f->eax = wait(arg[1]);                                       //passes the pid into wait()
      break;
    }
    case SYS_CREATE:
    {
      arg[1] = user_to_kernel_ptr((const void *)arg[1]);           //converts usr ptr to kernel ptr for name of file to be created
      f->eax = create((const char *)arg[1], (unsigned)arg[2]);     //passes file name and file descriptor into create()
      break;
    }
    case SYS_REMOVE:
    {
      arg[1] = user_to_kernel_ptr((const void *)arg[1]);           //converts usr ptr to kernel ptr for name of file to be deleted
      f->eax = remove((const char *)arg[1]);                       //passes the file name into remove()
      break;
    }
    case SYS_OPEN:
    {
      arg[1] = user_to_kernel_ptr((const void *)arg[1]);           //converts usr ptr to kernel ptr for name of file to be opened
      f->eax = open((const char *)arg[1]);                         //passes the file name into open()
      break;
    }
    case SYS_FILESIZE:
    {
      f->eax = filesize(arg[1]);                                   //passes the file descriptor of the file to be sized into filesize()
      break;
    }
    case SYS_READ:
    {
	  if(!is_valid_buffer((void *) arg[2], (unsigned) arg[3])) // validate buffer
		  exit(-1);	 
      arg[2] = user_to_kernel_ptr((const void *)arg[2]);           //converts the usr ptr for the buffer to a kernel ptr to be used for reading
      f->eax = read(arg[1], (void *)arg[2], (unsigned)arg[3]);     //passes the file descriptor, buffer and amount of bytes to be read into read()
      break;
    }
    case SYS_WRITE:
    {
	  if(!is_valid_buffer((void *) arg[2], (unsigned) arg[3])) // validate buffer
		  exit(-1);	 
      arg[2] = user_to_kernel_ptr((const void *)arg[2]);               //converts the usr ptr for the buffer to a kernel ptr to be used for writing
      f->eax = write(arg[1], (const void *)arg[2], (unsigned)arg[3]);  //passes the file descriptor, buffer and amount of bytes to be written into write()
      break;
    }
    case SYS_SEEK:
    {
      seek(arg[1], (unsigned)arg[2]);                             //passes the file descriptor and position in file into seek()
      break;
    }
    case SYS_TELL:
    {
      f->eax = tell(arg[1]);                                     //passes the file descriptor into tell()
      break;
    }
    case SYS_CLOSE:
    {
      close(arg[1]);                                            //passes the file descriptor into close()
      break;
    }
  }
  // END NEW CODE
}

// NEW CODE
/* Calls shutdown_power_off from devices/shutdown.c to shutdown the machine
   pintos is running on. */
void halt (void)
{
  shutdown_power_off();   //calls shutdown_power_off in devices/shutdown.c
}

/* Calls thread_exit from threads/thread.c to destroy the current thread. */
void exit (int status)
{
  struct thread *cur = thread_current();      //current thread
  if (thread_alive(cur->parent)) {
    cur->cp->status = status;     //if the current thread's parent is still alive, set its status in the child_process list of the parent
  }
  printf ("%s: exit(%d)\n", cur->name, status); //required by project description
  thread_exit();    //exit the thread
}

/* Calls process_execute from userprog/process.c to start a process named 
   "cmd_line." It passes the arguments given and return the new program
   id as pid. Returns -1 if not successful. */
pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);    //starts a new thread from file passed to command line and gets its thread id
  struct child_process *cp = get_child_process(pid);    //tries to get a child process with this id from the current thread
  if (NULL == cp) {
    return ERROR;   //if pid was not in the child list, return error
  }
  while (cp->load == NOT_LOADED) {
    barrier();    //otherwise wait until the thread loads, barrier to prevent optimization here
  }
  if (cp->load == LOAD_FAIL) {
    return ERROR;     //if child process fails to load, return error
  }
  return pid;   //otherwise return its id
}

/* Calls process_wait in process.c to wait for the process
   with pid pid to exit and then returns its exit code. */
int wait (pid_t pid)
{
  return process_wait(pid);   //waits for the thread with pid to die, then returns its exit code
}

/* Creates a new file called "file" using filesys_create from
   filesys/filesys.c and initializes it to initial_size in
   bytes. Returns true if success or false if not. */
bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&file_lock);   //acquire lock
  bool success = filesys_create(file, initial_size);    //try to create file
  lock_release(&file_lock);   //release lock
  return success;   //returns bool whether the file was created or not
}

/* Removes a file called "file" using filesys_remove from
   filesys/filesys.c. Returns true if successful or false if not.*/
bool remove (const char *file)
{
  lock_acquire(&file_lock);   //acquire lock
  bool success = filesys_remove(file);    //try to remove file
  lock_release(&file_lock);   //release lock
  return success;   //returns whether the file was removed or not
}

/* Opens the file called "file" using filesys_open from 
   filesys/filesys.c. Returns the integer file descriptor 
   as fd and -1 if it fails. */
int open (const char *file)
{
  lock_acquire(&file_lock);   //acquire the lock
  struct file *f = filesys_open(file);    //try to open the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not opened, release lock
    return ERROR;   //return error
  }
  int fd = process_add_file(f);   //otherwise, add the file to the process's list
  lock_release(&file_lock);   //release the lock
  return fd;    //return the file descriptor of the lock
}

/* Returns the file size of the file with file descriptor
   fd by calling process_get_file to get the file and
   file_length from filesys/file.c to get the length. */
int filesize (int fd)
{
  lock_acquire(&file_lock);   //acquire the lock
  struct file *f = process_get_file(fd);    //try to get the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not found, release the lock
    return ERROR;   //return error
  }
  int size = file_length(f);    //get the size of the file
  lock_release(&file_lock);   //release the lock
  return size;    //return the size of the file
}

/* Reads "size" number of bytes from the file with file
   descriptor fd into the buffer passed in. It does this
   by calling process_get_file, then reading the first "size"
   bytes by calling file_read from filesys/file.c. */
int read (int fd, void *buffer, unsigned size)
{
  //If we're using the standard input buffer...
  if (fd == STDIN_FILENO)
	{
	  unsigned i;
	  uint8_t* local_buffer = (uint8_t *) buffer;
	  for (i = 0; i < size; i++)
	  {
	    local_buffer[i] = input_getc();
	  }
	  return size;
	}
  //Otherwise, ...
  lock_acquire(&file_lock); //acquire the lock
  struct file *f = process_get_file(fd);    //try to get the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not found, relase the lock
    return ERROR;   //return error
  }
  int bytes = file_read(f, buffer, size);   //read the first size bytes from file f into the buffer
  lock_release(&file_lock);   //release the lock
  return bytes;   //return the number of bytes written
}

/* Writes "size" number of bytes from the buffer to 
   the file with file descriptor "fd."  It does this
   by getting the file with process_get_file and
   writing with file_write from file_write from
   filesys/file.c. */
int write (int fd, const void *buffer, unsigned size)
{
  //If we're using the standard output buffer...
  if (fd == STDOUT_FILENO)
	{
	  putbuf(buffer, size);
	  return size;
	}
  //Otherwise...
  lock_acquire(&file_lock);   //acquire the lock
  struct file *f = process_get_file(fd);    //try to get the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not found, release the lock
    return ERROR;   //return error
  }
  int bytes = file_write(f, buffer, size);    //write the first size bytes using the buffer into the file f
  lock_release(&file_lock);   //release the lock
  return bytes;   //return the number of bytes written
}

/* Changes the next byte to be read or written to 
   "position" bytes into the file with file descriptor
   "fd." It does this by calling process_get_file and then
   file_seek from filesys/file.c. */
void seek (int fd, unsigned position)
{
  lock_acquire(&file_lock);   //acquire the lock
  struct file *f = process_get_file(fd);    //try to get the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not found, release the lock
    return;   //return without seeking
  }
  file_seek(f, position);   //changes the next byte to be read or written to position
  lock_release(&file_lock);   //release the lock
  return;
}

/* Returns the next byte to be read or written in open
   file with file descriptor fd in bytes from the beginning
   of the file. It does this by calling process_get_file
   then file_tell from filesys/file.c. */
unsigned tell (int fd)
{
  lock_acquire(&file_lock);   //acquire the lock
  struct file *f = process_get_file(fd);    //try to get the file
  if (NULL == f) {
    lock_release(&file_lock);   //if the file was not found, release the lock
    return ERROR;   //return error
  }
  off_t offset = file_tell(f);    //get the offset byte from file_tell
  lock_release(&file_lock);   //release the lock
  return offset;    //return the offset from file_tell
}

/* Closes the open file with file descriptor "fd."  It does
   this by calling process_get_file then file_close from
   filesys/file, and finally process_close_file. */
void close (int fd)
{
  lock_acquire(&file_lock); //acquire the lock
  process_close_file(fd);   //close the file with file descriptor fd
  lock_release(&file_lock);   //release the lock
  return;   //return
}

/* Converts virtual address vaddr to the address of the
   pointer to the page of the virtual address using the
   pagedir_get_page from userprog/pagedir.c. */
int user_to_kernel_ptr(const void *vaddr)
{
  if (!is_valid_ptr(vaddr))    //if the virtual address is not a user's, exit the thread
	{
	  exit(-1); // exiting with error
	}
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);   //Otherwise, get the pointer to the kernel virtual address for current thread
  if (NULL == ptr)   //if we get a null pointer due to vaddr being unmapped, exit the thread
	{
	  exit(-1); // exiting with error
	}
  return (int) ptr;   //otherwise, return the kernel virtual address corresponding to the "physical address"
}

/* Gets the current max file descriptor from the current thread,
   increments by one and gives this new file descriptor to 
   the file f and adds it to the thread's list of files. Returns
   the new file descriptor. */
int process_add_file (struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));    //create new process_file
  pf->file = f;   //set its file to f
  pf->fd = thread_current()->max_fd;    //set its fd to the new fd of the current thread
  thread_current()->max_fd++;   //increment fd for next file
  list_push_back(&thread_current()->files, &pf->elem);    //add the process_file to the list of files
  return pf->fd;    //return the file descriptor
}

/* Goes through the current thread's open files and tries to return the one with 
   the correct file descriptor. If it doesn't find the file, it returns NULL. */
struct file* process_get_file (int fd)
{
  struct thread *cur = thread_current();    //get the current thread
  struct list_elem *file_elem;    //file element for iteration through files list
  //for each file in the files list...
  for (file_elem = list_begin(&cur->files); file_elem != list_end(&cur->files); file_elem = list_next(file_elem)) {
    struct process_file *pf = list_entry(file_elem, struct process_file, elem);     //get the process_file
    if (fd == pf->fd) {
      return pf->file;    //if the file descriptor is the one we're looking for, return the file
    }
  }
  return NULL;    //if we didn't find it, return NULL
}

/* Goes through the list of files opened by the current thread and looks for 
   one with the correct fd. If it finds it, it closes the file and removes it 
   from the list of files. If fd = CLOSE_ALL (-1), then all files are closed. */
void process_close_file (int fd)
{
  struct thread *cur_thread = thread_current();   //get the current thread
  struct list_elem *next_elem, *cur_elem = list_begin(&cur_thread->files);    //list elements for iterating through the files list
  //while we haven't went through the whole list
  while (cur_elem != list_end(&cur_thread->files)) {
    next_elem = list_next(cur_elem);    //set the next element
    struct process_file *pf = list_entry(cur_elem, struct process_file, elem);    //get process file for current element
    if (fd == pf->fd || fd == CLOSE_ALL) {    //if the file descriptor is the one passed in, or if we're trying to close all files
      file_close(pf->file);   //close the file
      list_remove(&pf->elem);   //remove it from the list
      free(pf);   //free the file
      if (fd != CLOSE_ALL) {
        return;   //if we're not closing all files, we're done
      }
    }
    cur_elem = next_elem;   //if we didn't find the element yet, or we're closing all files, we look at the next file
  }
  return;   //return
}

/* Creates a new child process and adds it to the back of the currrent
   thread's child list. Returns the new process. */
struct child_process* add_child_process(int pid) {
  struct child_process *cp = malloc(sizeof(struct child_process));    //create new child process
  //initialize values
  cp->pid = pid;
  cp->load = NOT_LOADED;
  cp->wait = false;
  cp->exit = false;
  lock_init(&cp->wait_lock);
  list_push_back(&thread_current()->child_list, &cp->elem); //add to the parent's child list
  return cp;  //return a pointer to the new child process
}

/* Looks for a process in the current thread's child list with the 
   corresponding pid. Returns the child process if found, otherwise
   returns NULL. */
struct child_process* get_child_process(int pid)
 {
  struct thread *cur = thread_current();    //get the current thread
  struct list_elem *child_elem;   //element to allow iteration through the child list
  //for each child in the child list
  for (child_elem = list_begin(&cur->child_list); child_elem != list_end(&cur->child_list); child_elem = list_next(child_elem)) 
  {
    struct child_process *cp = list_entry(child_elem, struct child_process, elem);  //get a pointer to the actual process
  if (pid == cp->pid) {
      return cp;    //if the pids match, return the child process
	}
  }
  return NULL;  //if we can't find the child process in the list
}

/* Removes the child process from the child list, and frees up
   the space it took up. */
void remove_child_process(struct child_process *cp) {
  list_remove(&cp->elem);   //remove the child from the list
  free(cp);   //free the space of the child
  return;   //return
}

/* Removes all child processes*/
void remove_child_processes() {
  struct thread *cur_thread = thread_current();   //get the current thread
  struct list_elem *next_elem, *cur_elem = list_begin(&cur_thread->child_list);   //list elements for iteration through the child list
  //while we haven't made it through the whole list
  while (cur_elem != list_end(&cur_thread->child_list)) {
    next_elem = list_next(cur_elem);    //set the next element
    struct child_process *cp = list_entry(cur_elem, struct child_process, elem);  //get the child process
    list_remove(&cp->elem);   //remove the child process
	  free(cp);   //free its space
    cur_elem = next_elem;   //continue on the next element
  }
  return;   //return
}

/* Checks that a v address is valid by seeing if it is
	a user's and does not exceed the bottom of the v address
	space. */
bool is_valid_ptr(const void *vaddr)
{
	return (is_user_vaddr(vaddr) && vaddr >= VADDR_BOTTOM);
}

/* Checks that a buffer with given size is valid by iterating
	through each element in the buffer and checking if the 
	element is a valid pointer. If any one of them is not,
	returns false, otherwise returns true. */
bool is_valid_buffer(void* buffer, unsigned size)
{
	char* loc_buffer = (char *) buffer;
	for (unsigned i = 0; i < size; i++)
	{
		if (!is_valid_ptr((const void *) loc_buffer))
			return false;
		else
			loc_buffer++;
	}
	return true;
}
// END NEW CODE