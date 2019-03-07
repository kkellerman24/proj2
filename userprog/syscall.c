#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// NEW CODE
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"   //needed for halt
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define ARG_MAX 4		/* Maximum number of arguments to pass to a system call */
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
  for (i = 0; i < ARG_MAX; i++)
  {
    arg[i] = *((int *)f->esp + i);  //add arguments to the arg array
  }
  switch (arg[0])   //first arg determines the call to make
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      exit(arg[1]);
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
      arg[2] = user_to_kernel_ptr((const void *)arg[2]);           //converts the usr ptr for the buffer to a kernal ptr to be used for reading
      f->eax = read(arg[1], (void *)arg[2], (unsigned)arg[3]);     //passes the file descriptor, buffer and amount of bytes to be read into read()
      break;
    }
    case SYS_WRITE:
    {
      arg[2] = user_to_kernel_ptr((const void *)arg[2]);               //converts the usr ptr for the buffer to a kernal ptr to be used for writing
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
  shutdown_power_off();
}

/* Calls thread_exit from threads/thread.c to destroy the current thread. */
void exit (int status)
{
  struct thread *parent = thread_current()->parent;
  if (NULL != parent) {
    struct child_process *cp = get_child_process(thread_current()->tid);
    if (cp->wait) {
      cp->status = status;
      //release wait lock
    }
  }
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

/* Calls process_execute from userprog/process.c to start a process named 
   "cmd_line." It passes the arguments given and return the new program
   id as pid. Returns -1 if not successful. */
pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process *cp = get_child_process(pid);
  if (NULL == cp) {
    return ERROR;   //if pid was not in the child list, return error
  }
  while (cp->load == NOT_LOADED) {
    //block thread
  }
  if (cp->load == LOAD_FAIL) {
    return ERROR;     //if child process fails to load, return error
  }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called "file" using filesys_create from
   filesys/filesys.c and initializes it to initial_size in
   bytes. Returns true if success or false if not. */
bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}

/* Removes a file called "file" using filesys_remove from
   filesys/filesys.c. Returns true if successful or false if not.*/
bool remove (const char *file)
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}

/* Opens the file called "file" using filesys_open from 
   filesys/filesys.c. Returns the integer file descriptor 
   as fd and -1 if it fails. */
int open (const char *file)
{
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  int fd = process_add_file(f);
  lock_release(&file_lock);
  return fd;
}

/* Returns the file size of the file with file descriptor
   fd by calling process_get_file to get the file and
   file_length from filesys/file.c to get the length. */
int filesize (int fd)
{
  lock_acquire(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  int size = file_length(f);
  lock_release(&file_lock);
  return size;
}

/* Reads "size" number of bytes from the file with file
   descriptor fd into the buffer passed in. It does this
   by calling process_get_file, then reading the first "size"
   bytes by calling file_read from filesys/file.c. */
int read (int fd, void *buffer, unsigned size)
{
  //what is going on here?????
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
  lock_acquire(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  int bytes = file_read(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

/* Writes "size" number of bytes from the buffer to 
   the file with file descriptor "fd."  It does this
   by getting the file with process_get_file and
   writing with file_write from file_write from
   filesys/file.c. */
int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
	{
	  putbuf(buffer, size);
	  return size;
	}
  lock_acquire(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  int bytes = file_write(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

/* Changes the next byte to be read or written to 
   "position" bytes into the file with file descriptor
   "fd." It does this by calling process_get_file and then
   file_seek from filesys/file.c. */
void seek (int fd, unsigned position)
{
  lock_release(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  file_seek(f, position);
  lock_release(&file_lock);
  return;
}

/* Returns the next byte to be read or written in open
   file with file descriptor fd in bytes from the beginning
   of the file. It does this by calling process_get_file
   then file_tell from filesys/file.c. */
unsigned tell (int fd)
{
  lock_release(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  off_t offset = file_tell(f);
  lock_release(&file_lock);
  return offset;
}

/* Closes the open file with file descriptor "fd."  It does
   this by calling process_get_file then file_close from
   filesys/file, and finally process_close_file. */
void close (int fd)
{
  lock_release(&file_lock);
  struct file *f = process_get_file(fd);
  if (NULL == f) {
    lock_release(&file_lock);
    return ERROR;
  }
  process_close_file(fd);
  lock_release(&file_lock);
}

/* Converts virtual address vaddr to the address of the
   pointer to the page of the virtual address using the
   pagedir_get_page from userprog/pagedir.c. */
// Need more help understanding this????????
int user_to_kernel_ptr(const void *vaddr)
{
  if (!is_user_vaddr(vaddr))    //if the virtual address is not a user's, exit the thread
	{
	  thread_exit();
	  return 0;
	}
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);   //Otherwise, get the pointer to the kernal virtual address for current thread
  if (NULL == ptr)   //if we get a null pointer due to vaddr being unmapped, exit the thread
	{
	  thread_exit();
	  return 0;
	}
  return (int) ptr;   //otherwise, return the kernal virtual address corresponding to the physical address
}

/* Gets the current max file descriptor from the current thread,
   increments by one and gives this new file descriptor to 
   the file f and adds it to the thread's list of files. Returns
   the new file descriptor. */
int process_add_file (struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->fd = thread_current()->max_fd;
  thread_current()->max_fd++;
  list_push_back(&thread_current()->files, &pf->elem);
  return pf->fd;
}

/* Goes through the current thread's open files and tries to return the one with 
   the correct file descriptor. If it doesn't find the file, it returns NULL. */
struct file* process_get_file (int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *file_elem;
  for (file_elem = list_begin(&cur->files); file_elem != list_end(&cur->files); file_elem = list_next(file_elem)) {
    struct process_file *pf = list_entry(file_elem, struct process_file, elem);
    if (fd == pf->fd) {
      return pf->file;
    }
  }
  return NULL;
}

/* Goes through the list of files opened by the current thread and looks for 
   one with the correct fd. If it finds it, it closes the file and removes it 
   from the list of files. If fd = CLOSE_ALL (-1), then all files are closed. */
void process_close_file (int fd)
{
  struct thread *cur_thread = thread_current();
  struct list_elem *cur_elem, *next_elem;
  while (cur_elem != list_end(&cur_thread->files)) {
    next_elem = list_next(cur_elem);
    struct process_file *pf = list_entry(cur_elem, struct process_file, elem);
    if (fd == pf->fd || fd == CLOSE_ALL) {
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      if (fd != CLOSE_ALL) {
        return;
      }
    }
    cur_elem = next_elem;
  }
  return;
}
// END NEW CODE
