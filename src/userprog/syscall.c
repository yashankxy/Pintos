#include "userprog/syscall.h"
#include <stdlib.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
typedef int pid_t;
/* System calls. */
static void syscall_halt (void);
static void syscall_exit (const uint8_t *args);
static pid_t syscall_exec (const uint8_t *args);
static int syscall_wait (const uint8_t *args);
static bool syscall_create (const uint8_t *args);
static bool syscall_remove (const uint8_t *args);
static int syscall_open (const uint8_t *args);
static int syscall_filesize (const uint8_t *args);
static int syscall_read (const uint8_t *args);
static int syscall_write (const uint8_t *args);
static void syscall_seek (const uint8_t *args);
static unsigned syscall_tell (const uint8_t *args);
static void syscall_close (const uint8_t *args);

static int get_new_fd(void);
static struct user_open_files*fd_info(struct thread *t, int fd);

/*Function to return a unique fd*/
static int get_new_fd(){
  static int fd_counter = 2;           
  return fd_counter++;
}

struct lock file_access_lock;
/* Map each system call number to its respective function. */
static int (*syscall_map[])(const uint8_t *) = 
{
  [SYS_HALT] = syscall_halt,
  [SYS_EXIT] = syscall_exit,
  [SYS_EXEC] = syscall_exec,
  [SYS_WAIT] = syscall_wait,
  [SYS_CREATE] = syscall_create,
  [SYS_REMOVE] = syscall_remove,
  [SYS_OPEN] = syscall_open,
  [SYS_FILESIZE] = syscall_filesize,
  [SYS_READ] = syscall_read,
  [SYS_WRITE] = syscall_write,
  [SYS_SEEK] = syscall_seek,
  [SYS_TELL] = syscall_tell,
  [SYS_CLOSE] = syscall_close
};
	
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Read the value starting at addr into ptr (copy size bytes).
   Return true if successful and false otherwise. */
static bool
read_mem (const uint8_t *addr, void *ptr, int size)
{
  int32_t read_val;
  int i;

  for (i = 0; i < size; i++)
    {
      if (-1 == get_user(addr + i)|| addr == NULL || 
        !is_user_vaddr (addr + i))
        return false;
      read_val = get_user(addr + i);
      *(char*)(ptr + i) = read_val & 0xff;
    }

  return true;
}

/* Read the int argument in position pos of args. Return
   true if successful and false otherwise. */
static bool
get_int_arg (const uint8_t *args, int pos, int *int_ptr)
{
  return read_mem (args + pos * sizeof (int), int_ptr, sizeof(int));
}

void
syscall_init (void) 
{
  lock_init (&file_access_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num;
  int syscall_map_size = sizeof (syscall_map) / sizeof (syscall_map[0]);

  if(f->esp>PHYS_BASE)
    thread_exit ();

  /* Read the system call number from the stack. */
  if (!get_int_arg (f->esp, 0, (int *) &syscall_num))
    thread_exit ();
  if (!put_user(f->esp, syscall_num))
    thread_exit ();

  /* Call the appropriate system call. */
  if (syscall_num > 0 && syscall_num < syscall_map_size)
    f->eax = syscall_map[syscall_num] (f->esp + sizeof (int));
  else
    f->eax = -1;
}

/*Terminates Pintos by calling shutdown_power_off().
args: void*/
static void
syscall_halt ()
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. 
args: int status*/
static void
syscall_exit (const uint8_t *args)
{
  int status;
  // validate args
  if (!get_int_arg (args, 0, &status))
    thread_exit ();

  thread_current ()->exit_status = status;
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing any given 
arguments, and returns the new process's program id (pid).
args: const char *cmd_line */
static tid_t
syscall_exec (const uint8_t *args)
{
  void* cmdline;
  
  // get first argument and verify it's valid
  if(!read_mem(args, &cmdline, sizeof (cmdline)))
    thread_exit ();

  // validate address
  if(get_user (cmdline) == -1)
    thread_exit ();

  return process_execute (cmdline);
}

/* Waits for a child process pid and retrieves the child's exit status.
args: pid_t pid*/
static int
syscall_wait (const uint8_t *args)
{
  pid_t pid;

  if (!read_mem (args, &pid, sizeof (pid)))
    thread_exit ();

  return process_wait (pid);
}

/* Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise.
args: const char *file, unsigned initial_size*/
static bool
syscall_create (const uint8_t *args)
{
  const char *file;
  unsigned initial_size;

  // Validate args
  if(!read_mem (args, &file, sizeof (file)) || 
      !read_mem (args + 4, &initial_size, sizeof (initial_size)))
    thread_exit ();
  
  // Validate the file
  if(get_user (file) == -1)
    thread_exit ();

  lock_acquire (&file_access_lock);
  bool return_val = filesys_create (file, initial_size);
  lock_release (&file_access_lock);
  return return_val;
}

/* Deletes the file called file. Returns true if successful, false otherwise.
args: const char *file*/
static bool
syscall_remove (const uint8_t *args)
{
  const char *file;
  bool return_val = false;
  // Validate args
  if(!read_mem (args, &file, sizeof (file)))
    thread_exit ();
  
  // Validate the file pointer
  if(get_user (file) == -1)
    thread_exit ();
  
  lock_acquire (&file_access_lock);
  return_val = filesys_remove (file);
  lock_release (&file_access_lock);

  return return_val;
}

/*Opens the file called file. Returns a nonnegative integer handle 
called a "file descriptor" (fd), or -1 if the file could not be opened.
args: const char *file*/
static int
syscall_open (const uint8_t *args)
{
  const char *file;
  struct user_open_files* new_fd_struct ;
  int new_fd = -1;

  // Validate args
  if(!read_mem (args, &file, sizeof (file)))
    thread_exit ();
  if(get_user (file) == -1)
    thread_exit ();

  // Create space to save user_open_files struct
  new_fd_struct = (struct user_open_files*) 
                  malloc (sizeof (struct user_open_files));

  lock_acquire (&file_access_lock);
  struct file *file_open = NULL;
  file_open = filesys_open (file);
   if (file_open == NULL)
    {
      free (new_fd_struct);
      lock_release (&file_access_lock);
      return -1;
    }
  // If file is found, populate the created user_open_files object and save
  // it in the current thread open_fd_list
  new_fd_struct->file = file_open;
  new_fd = get_new_fd ();
  new_fd_struct->fd = new_fd;
  list_push_back (&thread_current ()->open_fd_list, &new_fd_struct->fd_elem);
  lock_release (&file_access_lock);
  return new_fd;
}

/* Returns the size, in bytes, of the file open as fd.
args: int fd*/
static int
syscall_filesize (const uint8_t *args)
{
  struct user_open_files *fd_struct = NULL; 
  int fd;
  int filesize = -1;

  // Validate args
  if(!read_mem (args, &fd, sizeof (fd)))
    thread_exit();
  lock_acquire (&file_access_lock);
  struct thread *cur = thread_current();

  //Look for fd inside the current thread's user_open_files
  fd_struct = fd_info (cur, fd);
  if (fd_struct != NULL)
    filesize = file_length (fd_struct->file);
  lock_release (&file_access_lock);

  return filesize;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number 
of bytes actually read .
args: int fd, void *buffer, unsigned size*/
static int
syscall_read (const uint8_t *args)
{
  int fd;
  void *buffer;
  unsigned size;
  int bytes_read;

  // Validate args 
  if(!read_mem (args, &fd, sizeof (fd)) || 
      !read_mem (args + 4, &buffer, sizeof (buffer))||
      !read_mem (args + 8, &size, sizeof (size)))
    thread_exit ();
  if(get_user (buffer) == -1 || !is_user_vaddr (buffer))
    thread_exit ();
  if(get_user (buffer+size-1) == -1 || !is_user_vaddr (buffer+size-1))
    thread_exit ();

  struct user_open_files *target_fd = NULL;
  struct thread *cur = thread_current();
  //Look for fd inside the current thread's user_open_files
  target_fd = fd_info (cur, fd);
  if (target_fd == NULL)
    thread_exit ();
  bytes_read = file_read (target_fd->file, buffer, size);

  return bytes_read;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
bytes actually written.
args: int fd, const void *buffer, unsigned size*/
static int
syscall_write (const uint8_t *args)
{
  int fd;
  void *buffer;
  unsigned size;
  int bytes_written;

  // Validate args
  if(!read_mem (args, &fd, sizeof(fd)) || 
      !read_mem (args + 4,&buffer, sizeof(buffer))||
      !read_mem (args + 8,&size, sizeof(size)))
    thread_exit ();

  /* Write to console. */
  if (fd == 1)
    {
      lock_acquire (&file_access_lock);
      putbuf (buffer, size);
      bytes_written = size;
      lock_release (&file_access_lock);
      return bytes_written;
    }
  
  // Validate args
  if (get_user (buffer) == -1 || !is_user_vaddr (buffer))
    thread_exit ();
  if (get_user (buffer+size-1) == -1 || !is_user_vaddr (buffer+size-1))
    thread_exit ();

  struct user_open_files *target_fd = NULL;
  struct thread *cur = thread_current ();
  //Look for fd inside the current thread's user_open_files
  target_fd = fd_info (cur, fd);
  if (target_fd == NULL)
    thread_exit ();
  bytes_written = file_write (target_fd->file, buffer, size);
  return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position
args: int fd, unsigned position*/
static void
syscall_seek (const uint8_t *args)
{
  int fd;
  unsigned position;
  if(!read_mem (args, &fd, sizeof(fd)) || 
      !read_mem (args + 4, &position, sizeof (position)))
    thread_exit();
  
  struct user_open_files *target_fd = NULL;
  struct thread *cur = thread_current();
  lock_acquire (&file_access_lock);
  //Look for fd inside the current thread's user_open_files
  target_fd = fd_info (cur, fd);
  if (target_fd == NULL || &target_fd->file == NULL)
    thread_exit ();
  file_seek (target_fd->file, position);
  lock_release (&file_access_lock);
}

/* Returns the position of the next byte to be read or written in open file 
fd, expressed in bytes from the beginning of the file.
args: int fd*/
static unsigned
syscall_tell (const uint8_t *args)
{
  int fd;
  int position = -1;
  // Validate args
  if(!read_mem (args, &fd, sizeof(fd)))
    thread_exit ();
  
  struct user_open_files *target_fd = NULL;
  struct thread *cur = thread_current();
  lock_acquire (&file_access_lock);
  //Look for fd inside the current thread's user_open_files
  target_fd = fd_info (cur, fd);
  if (target_fd == NULL || &target_fd->file == NULL)
    thread_exit ();
  position = file_tell (target_fd->file);
  lock_release (&file_access_lock);
  return position;
}

/* Closes file descriptor fd.
args: int fd*/
static void
syscall_close (const uint8_t *args)
{
  struct user_open_files *fd_struct; 
  int fd;
  //Validate args
  if(!read_mem (args, &fd, sizeof (fd)))
    thread_exit ();

  lock_acquire (&file_access_lock);
  struct thread *cur = thread_current ();
  //Look for fd inside the current thread's user_open_files
  fd_struct = fd_info (cur, fd);
  if (fd_struct != NULL)
    {
      file_close (fd_struct->file);
      list_remove (&(fd_struct->fd_elem));
    }
  lock_release (&file_access_lock);
}

/* Returns user_open_files struct corresponding to fd in thread t's
user_open_files. Returns NULL if no such element is found
*/
static struct user_open_files*
fd_info(struct thread *t, int fd)
{
  struct list_elem *elem;
  struct user_open_files *return_info = NULL;
  if (t == NULL || fd < 2)
    return return_info;
  if (&t->open_fd_list != NULL)
    {
      // Iterate through each element and find matching fd
      for (elem = list_begin (&t->open_fd_list);
        elem != list_end (&t->open_fd_list); elem = list_next (elem))
        {
          return_info = list_entry (elem, struct user_open_files, fd_elem);
          if (return_info->fd == fd)
            {
              return return_info;
            }
        }
    }
  return return_info;
}