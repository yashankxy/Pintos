#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/*Structure to keep track of each fd generated when opening a file by user
program*/
struct user_open_files
{
  int fd;                            /* File descriptor */
  struct file *file;                 /* Pointer to file*/
  struct list_elem fd_elem;          /* List elem for each thread*/
};

#endif /* userprog/process.h */
