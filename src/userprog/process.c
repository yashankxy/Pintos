#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *prog_name, char *prog_args, 
                  void (**eip) (void), void **esp);

struct p_args
{
  char *prog_name;
  char *prog_args;
  tid_t parent_tid;
  struct semaphore sema;
  struct thread *child;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  struct p_args args;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parses fn_copy to retrieve the program name (the first
     token in the delimited string) and then stores the 
     rest as the program arguments. */
  args.prog_name = strtok_r (fn_copy, " ", &args.prog_args);
  args.parent_tid = thread_current ()->tid;

  /* Create a new thread to execute FILE_NAME. */
  sema_init (&args.sema, 0);
  tid = thread_create (args.prog_name, PRI_DEFAULT, start_process, &args);
  if (tid != TID_ERROR)
    {
      /* Wait for the thread to start running and add it as a child of 
         the current thread. */
      sema_down (&args.sema);
      if (args.child != NULL)  
        list_push_back (&thread_current ()->children, 
                        &args.child->child_elem);
      else
        tid = TID_ERROR;
    }
  palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct p_args *args;
  struct intr_frame if_;
  bool success;

  args = args_;
  success = false;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Attempt to load the program with the given arguments. */
  if (load (args->prog_name, args->prog_args, &if_.eip, &if_.esp))
    {
      args->child = thread_current ();
      thread_current ()->parent_tid = args->parent_tid;
      success = true;
    }
  else
    args->child = NULL;

  sema_up (&args->sema);

  /* If load failed, quit. */
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur;
  struct thread *child = NULL;
  struct list_elem *elem;
  int res;

  cur = thread_current ();

  /* Search for the child with tid child_tid. */  
  for (elem = list_begin (&cur->children);
       elem != list_end (&cur->children); elem = list_next (elem))
    {
      child = list_entry (elem, struct thread, child_elem);
      if (child->tid == child_tid)
        {
          list_remove (elem);
          break;
        }
    }

  /* Could not find child with tid child_tid. */
  if (child == NULL)
    return -1;

  /* Wait for the child to exit and then free it. */
  lock_acquire (&child->exit_lock);

  while (child->status != THREAD_EXITING)    
      cond_wait (&child->exit_cond, &child->exit_lock);

  lock_release (&child->exit_lock);

  res = child->exit_status;
  palloc_free_page (child);

  return res;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur;
  struct thread *child;
  uint32_t *pd;
  struct list_elem *elem;
  enum thread_status status;

  cur = thread_current ();

  // Release executable
  if (cur->executable_file){
    file_allow_write(cur->executable_file);
    file_close(cur->executable_file);
  }
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
      printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
    }

  /* Handle the exiting process' children, either orphaning
     them or freeing them as well if they are also exiting. */
  lock_acquire (&cur->exit_lock);
  for (elem = list_begin (&cur->children); elem != list_end (&cur->children);
       elem = list_next (elem))
    {
      child = list_entry (elem, struct thread, child_elem);
      
      lock_acquire (&child->exit_lock);
      
      child->parent_tid = TID_NONE;
      if (child->status == THREAD_EXITING)
          palloc_free_page (child);

      lock_release (&child->exit_lock);

      list_remove (elem);
    }
  
  // Clean and close each open fd
  struct user_open_files *clean_fd = NULL;
  if (&cur->open_fd_list != NULL)
  {
    for (elem = list_begin (&cur->open_fd_list);
        elem != list_end (&cur->open_fd_list); elem = list_next (elem))
    {
      free(clean_fd);
      struct user_open_files *return_info
          = list_entry (elem, struct user_open_files, fd_elem);
      file_close (return_info->file);
      clean_fd = return_info;
    }
    free(clean_fd);
  }

  /* If the parent process has not exited, then it still needs
     to read the exit status so cannot free the stack just yet. */
  if (cur->parent_tid != TID_NONE)
    {
      status = THREAD_EXITING;
      cond_signal (&cur->exit_cond, &cur->exit_lock);
    }
  else
    status = THREAD_DYING;
  
  intr_disable ();
  lock_release (&cur->exit_lock);
  cur->status = status;
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

#define MAX_ARGS_SIZE 512

static bool setup_stack (const char *program_name, char *args, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *prog_name, char *prog_args, 
      void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (prog_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", prog_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", prog_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (prog_name, prog_args, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  thread_current()->executable_file = file;
  file_deny_write (file);

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (const char *prog_name, char *prog_args, void **esp)
{
  uint8_t *kpage;
  uint8_t *top, *bot, *base;
  const char *arg;
  size_t len;
  int argc;
  bool success;

  success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      /* Start the stack in the page just below virtual address PHYS_BASE. */
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          /* Since the stack grows downwards, the bottom of the stack
             is PHYS_BASE and is where the arguments argv[x][...] 
             are stored. The top is where the pointers of the arguments 
             argv[x] are stored and later word aligned. */
          bot = PHYS_BASE;
          top = PHYS_BASE - MAX_ARGS_SIZE;
          base = top;
          argc = 0;

          /* First argument is always the program name. */
          arg = prog_name;

          /* Iterate over all arguments and push them onto the stack. */
          while (arg != NULL)
            {
              /* Copy the argument onto the stack, adding 1 to the
                 length to account for the null terminator. */
              len = strlen (arg) + 1;
              bot -= len;
              memcpy (bot, arg, len * sizeof (char));

              /* Copy the address of the newly added argument to
                 the argument pointers. */
              *((uint8_t **) top) = bot;
              top += sizeof (char *);

              /* Increment the argument count and retrieve the 
                 next argument (or NULL if it does not exist). */
              argc += 1;
              if (prog_args != NULL)
                arg = strtok_r (NULL, " ", &prog_args);
              else
                arg = NULL;
            }

          /* Move the argument pointers to its proper position in the
             stack following the arguments + word alignment if 
             needed, and adjust base to be the final location of
             the argument pointers. */
          bot = word_round_down (bot) - sizeof (char *);
          memmove (base + (bot - top), base, argc * sizeof (char *));
          base += bot - top;

          /* Set argv to be the beginning of the address pointers. */
          *((uint8_t **) (base - sizeof (char**))) = base;

          /* Set argc to be the argument count. */
          base -= sizeof (char **) + sizeof (argc);
          *((int *) base) = argc;

          /* Set a fake return address along with the stack pointer
             to be the base of the stack. */
          base -= sizeof (void *);
          *base = 0;
          *esp = base;
        }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
