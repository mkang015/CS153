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
#include "threads/synch.h"
#include "threads/thread.h"

//struct used to share between process_execute() in the invoking thread and
// start_process() inside the newly invoked thread
struct exec_helper
{
  const char* file_name; //program to load (entire command line)
  struct semaphore loadSema; //add semaphore for loading (for resource race cases)
  //add bool for determining if program loaded successfully
  bool isLoaded;
  //add other stuff you need to transfer between process_execute and process start
  // (hint, think of the children... need a way to add to the child's list, see below about thread's 
  //  child list)
  struct list_elem childelem; //save child to push to child_list
};

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

//min add
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct exec_helper exec;
  char thread_name[16];

  tid_t tid;

  //initialize the loaded status to false
  exec.isLoaded = false;

  //set exec file name
  exec.file_name = file_name;

  //initialize a semaphore for loading here
  sema_init(&exec.loadSema, 0); //set it to 0

  //add program name to thread_name
  // program name is the first token of file_name
  char* savePtr;
  char* cmd = palloc_get_page(0);
  if(cmd == NULL)
  	return TID_ERROR;

  const char* delim = " ";
  strlcpy(cmd, file_name, PGSIZE);
  char* command = strtok_r(cmd, delim, &savePtr);//take the path/command

  int i = 0;
  for(;command[i] != '\0'; ++i)
    thread_name[i] = command[i];
  thread_name[i] = '\0';

  palloc_free_page(cmd);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, &exec);
  if (tid != TID_ERROR)
  {
	//wait for new thread to finish loading
	sema_down(&exec.loadSema);

	//if program load successful, add new child to the list of this thread's children (mind your list_elems)
	// we need to check this list in process wait, when children are done, process wait can finish (see process wait)
	if(exec.isLoaded)
	{
		struct thread* t = thread_current();
		list_push_back(&t->childList, &exec.childelem); //push back threads, each thread has tid in it
												        // thread ids are in threads 
	}
	else
		return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct exec_helper* exec = aux;
  char *file_name = (char*)exec->file_name;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  //load finished
  sema_up(&exec->loadSema);

  /* If load failed, quit. */
  if (!success) 
    thread_exit ();


  //set the flag for successful load
  exec->isLoaded = true;

  struct thread* t = thread_current();
  t->thread_type = true; //min add, set the thread_type (true == user thread)


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
  struct thread *t = thread_current();
  struct list_elem e;

  //iterate through current thread's childList
  // find the child with child_tid
  for(e = list_begin(&t->childList); e != list_end(&t->childList); e = list_next(e))
  {
    struct thread* tmpT = list_entry(e, struct thread, elem); //get thread

  	//found
    if(tmpT->tid == child_tid)
	{
	  list_remove(e); //remove from list
	  //use semaphore in struct thread to recursively wait?
	  //sema_down(&tmpT->
	}
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if(cur->thread_type) //min add, come back and add check for halt system call
    printf("%s: exit(%d)\n", cur->name, cur->tid);

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
    }
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

static bool setup_stack (void **esp, const char* cmd_line);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmd_line, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  char file_name[NAME_MAX + 2];
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  char* charPtr; //for parsing
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //Use strtok_r to remove file_name from cmd_line
  char* cmd = palloc_get_page(0);
  char* delim = " ";
  strlcpy(cmd, cmd_line, PGSIZE);

  char* token = strtok_r(cmd, delim, &charPtr);
  strlcpy(file_name, token, sizeof(token)); //get the filename

  palloc_free_page(cmd);

  /* Open executable file. */
  file = filesys_open (file_name);
  t->openedFile = file; //to keep track of opened file for process exit
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  //Disable file write for 'file' here. GO TO BOTTOM. DON'T CHANGE ANYTHING IN THESE IF AND FOR STATEMENTS

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
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
  if (!setup_stack (esp, cmd_line))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //removed the file close because we will close it in process exit
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

// push (kpage, &ofs, &x, sizeof x), kpage is created in setup_stack....
// x is all the values argv, argc, and null (you need a null on the stack!)
// Be careful of the order of argv! Check the stack example

/* Pushes the SIZE bytes in BUF onto the stack in KPAGE, whose
page-relative stack pointer is *OFS, and then adjusts *OFS
appropriately.  The bytes pushed are rounded to a 32-bit
boundary.

If successful, returns a pointer to the newly pushed object.
On failure, returns a null pointer. */
static void* push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size) 
{
  //rounds up to 32
  size_t padsize = ROUND_UP (size, sizeof (uint32_t));

  if (*ofs < padsize)
    return NULL;

  *ofs -= padsize;
  memcpy (kpage + *ofs + (padsize - size), buf, size);
   
  return kpage + *ofs + (padsize - size);
}

static bool setup_stack_helper(const char* cmd_line, uint8_t* kpage, uint8_t* upage, void** esp)
{
  size_t ofs = PGSIZE; //used in push
  char* const null = NULL; //used for pushing nulls
  char* ptr; //strtok_r usage

  //need some other variables here
  char* token;
  char* cmd = NULL; //string to parse
  const char* delim = " ";
  int numTok = 0;

  strlcpy(cmd, cmd_line, sizeof(cmd_line));//make a copy to char*

  //parse and put in command line arguments, push each value
  //if any push() returns NULL, return false

  //get number of tokens
  while(1)
  {
    token = strtok_r(cmd, delim, &ptr);
	if(token == NULL)
	  break;
	numTok++;
	cmd = NULL;
  }

  char* arr[numTok]; //store tokens in array
  int i = 0;

  strlcpy(cmd, cmd_line, sizeof(cmd_line));//make a copy to char*

  //store them into array
  while(1)
  {
    token = strtok_r(cmd, delim, &ptr);
	if(token == NULL)
	  break;
	
	strlcpy(token, arr[i++], sizeof(token));
	cmd = NULL;
  }
  --i;//iterate backward

  //need to push tokens going backward
  while(i >= 0)
    if (push(kpage, &ofs, arr[i], sizeof(arr[i--])) == NULL)
	  return false;
  
  //push() a null (more precisely &null)
  //if push returned NULL, return false
  if (push(kpage, &ofs, &null, sizeof(&null)) == NULL)
    return false;
  
  //push argv addresses (ex. for the cmd_line added above) in reverse order
  // see the stack example on documentation for what "reversed" means
  i = numTok;

  while(i >= 0)
    if (push(kpage, &ofs, &arr[i--], sizeof(char*)) == NULL)
	  return false;

  // push argc, how can we determine argc?
  if (push(kpage, &ofs, &numTok, sizeof(int)) == NULL)
	return false;
  // push &null
  if (push(kpage, &ofs, &null, sizeof(&null)) == NULL)
    return false;

  // should you check for NULL returns?
 
  //set up the stack pointer. IMPORTANT make sure you use the right value here...
 
 *esp = upage + ofs;

  //if you made it this far, everything seems good, return true
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* cmd_line) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    uint8_t* upage = ((uint8_t*) PHYS_BASE) - PGSIZE;
    success = install_page (upage, kpage, true);

    if (success) //min add, if sucess at installing the page
	  success = setup_stack_helper(cmd_line, kpage, upage, esp);
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
