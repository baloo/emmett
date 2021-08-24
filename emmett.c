#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <asm/auxvec.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <glib.h>

#define ROUND_UP(N, S) ((((N) + (S)-1) / (S)) * (S))
#define ROUND_DOWN(N, S) ((N / S) * S)

static void process_signals(pid_t child);

GHashTable *htable;

struct watched_task {
	pid_t pid;
	bool in_exec;
	bool is_root;
	struct user user;
	int status;
	int error;
};

static struct watched_task *task_create()
{
	struct watched_task *task = malloc(sizeof(struct watched_task));
	memset(task, 0, sizeof(struct watched_task));
	return task;
}
static void task_destroy(void *data, void *user_data)
{
	struct watched_task *task = (struct watched_task *)data;
	if (task)
		free(task);
}

int ptrace_memcpy_from_child(struct watched_task *child, void *dst,
			     unsigned long src, size_t n)
{
	unsigned long scratch;

	while (n) {
		scratch = ptrace(PTRACE_PEEKDATA, child->pid, src, 0);
		memcpy(dst, &scratch, MIN(n, sizeof(unsigned long)));

		dst += sizeof(unsigned long);
		src += sizeof(unsigned long);
		if (n >= sizeof(unsigned long))
			n -= sizeof(unsigned long);
		else
			n = 0;
	}
	return 0;
}

int ptrace_memcpy_to_child(struct watched_task *child, unsigned long dst,
			   const void *src, size_t n)
{
	unsigned long scratch;

	while (n >= sizeof(unsigned long)) {
		if (ptrace(PTRACE_POKEDATA, child->pid, dst,
			   *((unsigned long *)src)) < 0)
			return -1;
		dst += sizeof(unsigned long);
		src += sizeof(unsigned long);
		n -= sizeof(unsigned long);
	}

	if (n) {
		scratch = ptrace(PTRACE_PEEKDATA, child->pid, dst, 0);
		if (child->error)
			return -1;
		memcpy(&scratch, src, n);
		if (ptrace(PTRACE_POKEDATA, child->pid, dst, scratch) < 0)
			return -1;
	}

	return 0;
}

void *ptrace_remote_syscall(struct watched_task *child, unsigned long sysno,
			    unsigned long p0, unsigned long p1,
			    unsigned long p2, unsigned long p3,
			    unsigned long p4, unsigned long p5)
{
	// We're right in the middle of nowhere here.
	// To make remote issue a syscall, we'll need to setup registers and
	// make it execute the couple asm instructions for a syscall. How do we
	// do that?
	//  - Setup registers
	//    Read the current registers and save them.
	//    Write our own.
	//    Execute syscall
	//    Read the result
	//    Write the old registers back
	//  - Execute syscall instructions
	//    We don't know where (or if) syscall instructions are present, so
	//    instead we'll read the code where the current instruction pointer
	//    is and save that. In that place we'll write the syscall
	//    instructions, setup registers, execute syscall, then rewrite the
	//    original data back in place.

	void *rv;
	int status;

	const uint8_t injection_buffer[] = {
	    0x0f, 0x05, // syscall
	    0xcc	// int3 (SIGTRAP)
	};
	uint8_t
	    new_data[ROUND_UP(sizeof(injection_buffer), sizeof(unsigned long))];
	uint8_t
	    old_data[ROUND_UP(sizeof(injection_buffer), sizeof(unsigned long))];

	struct user_regs_struct old_regs;
	ptrace(PTRACE_GETREGS, child->pid, NULL, &old_regs);
	ptrace(PTRACE_SETREGS, child->pid, NULL, &old_regs);

	void *injection_address =
	    (void *)ROUND_DOWN(old_regs.rip, sizeof(unsigned long));

	// Store data at injection_address
	ptrace_memcpy_from_child(child, old_data,
				 (unsigned long)injection_address,
				 sizeof(old_data));
	memcpy(&new_data, &old_data, sizeof(new_data));
	memcpy(&new_data, &injection_buffer, sizeof(injection_buffer));

	struct user_regs_struct regs;
	memset(&regs, 0, sizeof(struct user_regs_struct));
	regs.rax = sysno;			     // syscall number
	regs.rdi = p0;				     // arg0
	regs.rsi = p1;				     // arg1
	regs.rdx = p2;				     // arg2
	regs.r10 = p3;				     // arg3
	regs.r8 = p4;				     // arg4
	regs.r9 = p5;				     // arg5
	regs.rip = (unsigned long)injection_address; // next instruction

	// Write injection buffer to injection address
	ptrace_memcpy_to_child(child, (unsigned long)injection_address,
			       new_data, sizeof(new_data));

	ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);

	do {
		// For some reason, we need to PTRACE_CONT twice. We're only
		// called from a syscall-exit-stop location, so we should be
		// able to re-enter a syscall immediately, but RIP only bumps on
		// the second try.

		ptrace(PTRACE_CONT, child->pid, NULL, NULL);
		// We wrote int3 after the syscall, so the process will
		// immediately sigtrap on return.
		waitpid(child->pid, &child->status, WSTOPPED);
		// Read back the result
		ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
		rv = (void *)regs.rax;
	} while (regs.rip ==
		 injection_address); // If the screw does not go in, you just
				     // need a bigger hammer.

	// Restore the context
	ptrace(PTRACE_SETREGS, child->pid, NULL, &old_regs);
	// Write the injection buffer back to what it was
	ptrace_memcpy_to_child(child, (unsigned long)injection_address,
			       old_data, sizeof(old_data));

	return rv;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int status;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n",
			argv[0]);
		return 1;
	}

	if ((pid = fork()) == 0) {
		/* If open syscall, trace */
		struct sock_filter filter[] = {
		    BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
			     offsetof(struct seccomp_data, nr)),
		    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 0, 1),
		    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
		    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_gettimeofday, 0,
			     1),
		    BPF_STMT(BPF_RET + BPF_K,
			     SECCOMP_RET_ERRNO | (-EPERM & SECCOMP_RET_DATA)),
		    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
		};
		struct sock_fprog prog = {
		    .filter = filter,
		    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		};
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		/* To avoid the need for CAP_SYS_ADMIN */
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			return 1;
		}
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
			perror("when setting seccomp filter");
			return 1;
		}

		// Wait for parent to setup
		kill(getpid(), SIGSTOP);

		return execvp(argv[1], argv + 1);
	} else {
		waitpid(pid, &status, 0);
		ptrace(PTRACE_SETOPTIONS, pid, 0,
		       PTRACE_O_TRACESECCOMP/* | PTRACE_O_EXITKILL |
			   PTRACE_O_TRACEEXEC  | PTRACE_O_TRACECLONE |
			   PTRACE_O_TRACEFORK*/);

		htable = g_hash_table_new_full(NULL, NULL, NULL,
					       (GDestroyNotify)task_destroy);
		struct watched_task *task = task_create();
		task->pid = pid;
		task->is_root = true;
		g_hash_table_insert(htable, (gpointer)pid, task);

		process_signals(pid);

		g_hash_table_destroy(htable);
		return 0;
	}
}

static void process_signals(pid_t child)
{
	int status;
	int in_execve_syscall = 0;

	ptrace(PTRACE_CONT, child, 0, 0);
	while (1) {
		pid_t pid = wait(&status);
		printf("pid %d status %x\n", pid, status);
		struct watched_task *task =
		    g_hash_table_lookup(htable, (gpointer)pid);

		if (WSTOPSIG(status) == SIGTRAP &&
		    ((status >> 16) == PTRACE_EVENT_CLONE ||
		     (status >> 16) == PTRACE_EVENT_FORK)) {
			pid_t child_pid;
			ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid);

			struct watched_task *task = task_create();
			task->pid = child_pid;
			g_hash_table_insert(htable, (gpointer)child_pid, task);

			ptrace(PTRACE_CONT, pid, 0, 0);
			continue;
		} else if (status >> 8 ==
			       (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) &&
			   ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX,
				  0) == __NR_execve) {
			printf("SECCOMP execve\n");
			struct watched_task *task = task_create();
			task->pid = pid;
			task->in_exec = true;
			task->is_root = pid==child;
			g_hash_table_insert(htable, (gpointer)pid, task);

			//
			//        Functionally, a PTRACE_EVENT_SECCOMP stop
			//        functions comparably to a syscall-entry-stop
			//        (i.e., continuations  using  PTRACE_SYSCALL
			//               will cause syscall-exit-stops, the
			//               system call number may be changed and
			//               any other modified registers are
			//               visible to the to-be-ex‐
			//                      ecuted system call as well).
			//                      Note that there may be, but need
			//                      not have been a preceding
			//                      syscall-entry-stop.
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			continue;
		}
		printf("task %p\n", task);

		if (task == NULL)
			continue;
		printf("task->in_exec %d \n", task->in_exec);

		int stop_sig = WSTOPSIG(status);
		printf("stop_sig %d status >> 8 = %d \n", stop_sig,
		       status >> 8);

		/* Is it our filter for the execve syscall? */
		if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) &&
		    ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, 0) ==
			__NR_execve) {
			int ret_val =
			    ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, 0);
			if (ret_val == -ENOSYS) {
				task->in_exec = true;
				// We just entered the syscall, we have
				// to let the child continue until it
				// reaches the exit
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
			}
		} else if (status >> 8 ==
			   (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
			int ret_val =
			    ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, 0);
			task->in_exec = false;
			if (ret_val == -ENOSYS) {
				task->in_exec = true;
				// We just entered the syscall, we have
				// to let the child continue until it
				// reaches the exit
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
				continue;
			}
			//} else if (status >> 8 == SIGTRAP && task->in_exec) {
		} else if (stop_sig == SIGTRAP && task->in_exec) {
			int ret_val =
			    ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, 0);
			printf("in_exec %d\n", ret_val);
			task->in_exec = false;
			// Get the auxilliary vector, and reinject it
			// with our modified vdso

			struct user_regs_struct saved_regs;

			// Read the stack, and parse it
			// Stack is stored in the SP register.
			// it should look like:
			//  - argc
			//  - argv (multiple pointers to further up the stack)
			//  - envp (multiple pointers to further up the stack)
			//  - NULL
			//  - auxiliary vector
			//    List of tuples like:
			//      - id (int64)
			//      - data (int64/void*)
			//    this is terminated by id=NULL
			//
			// Here we're looking for the AT_SYSINFO_EHDR element of
			// the auxiliary vector we'll get the address in the
			// vector, and where it points to.
			//
			// Stack layout documentation:
			//   https://lwn.net/Articles/631631/

			// Fetch the stack address
			ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs);
			unsigned long rsp = saved_regs.rsp;
			printf("rsp %p\n", rsp);

			long child_addr;
			long argc = (long)ptrace(PTRACE_PEEKTEXT, pid, rsp, 0);
			// Don't need to read argv
			printf("argc %d\n", argc);

			// We now need to read the environ.
			unsigned long envp = saved_regs.rsp + 0x8 * (argc + 2);
			while ((long)ptrace(PTRACE_PEEKTEXT, pid, envp, 0) !=
			       0x0) {
				envp += 0x8;
			}
			unsigned long auxv_start = envp + 0x8;

			long id = 1;
			long offset = 0;
			unsigned long vdso_reg_addr = 0;
			unsigned long vdso = 0;
			while (id != 0) {
				id = (long)ptrace(PTRACE_PEEKTEXT, pid,
						  auxv_start + offset, 0);
				if (id == AT_SYSINFO_EHDR) {
					vdso_reg_addr =
					    auxv_start + offset + 0x8;
					vdso =
					    (long)ptrace(PTRACE_PEEKTEXT, pid,
							 vdso_reg_addr, 0);
					break;
				}

				offset += 0x10;
			}
			printf("vdso %p\n", vdso);

			if (vdso != 0) {
				// we now have the vdso address
				// time to replace it
				//
				// We'll load our own vdso, then mmap a new
				// place in the child to store it.

				int vdso_fd = open("./vdso.so", 0);
				struct stat sb;
				fstat(vdso_fd, &sb);
				size_t new_vdso_size =
				    ROUND_UP(sb.st_size, 4096);

				void *new_vdso_addr = ptrace_remote_syscall(
				    task, __NR_mmap, NULL, new_vdso_size,
				    PROT_READ | PROT_WRITE,
				    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
				printf("new_vdso_addr %p\n", new_vdso_addr);
				void *vdso_content =
				    mmap(NULL, sb.st_size, PROT_READ,
					 MAP_SHARED, vdso_fd, 0);

				// Copy our vdso in the new segment
				ptrace_memcpy_to_child(task, new_vdso_addr,
						       vdso_content,
						       sb.st_size);
				munmap(vdso_content, sb.st_size);
				close(vdso_fd);

				// Friends dont let friends run with a
				// PROT_WRITE|PROT_EXEC mem segments
				ptrace_remote_syscall(
				    task, __NR_mprotect, new_vdso_addr,
				    new_vdso_size, PROT_EXEC | PROT_READ, 0, 0,
				    0);

				// Then rewrite the vdso pointer in the stack.
				long out =
				    (long)ptrace(PTRACE_POKETEXT, pid,
						 vdso_reg_addr, new_vdso_addr);
			}
			printf("done inject\n");

			ptrace(PTRACE_CONT, pid, 0, 0);

		} else if (WIFEXITED(status)) {
			printf("task->isroot %d pid=%d task->pid=%d child=%d\n", task->is_root, pid, task->pid, child);
			if (task->is_root)
				return;
			printf("exited\n");

			g_hash_table_remove(htable, (gpointer)pid);
			//ptrace(PTRACE_CONT, pid, 0, 0);
		} else {
			// Not an handled signal, just let the program
			// go, should it raise in seccomp kernel will
			// stop it.
			ptrace(PTRACE_CONT, pid, 0, 0);
		}
	}
}
