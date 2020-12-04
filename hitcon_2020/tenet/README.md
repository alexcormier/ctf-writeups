# Tenet

**CTF:** [HITCON CTF 2020](https://ctf2020.hitcon.org/)

**Track:** misc, reverse

**Description:** You have to start looking at the world in a new way.

**Designer:** david942j

## Give it a try?

If you want to give this challenge a try before reading the writeup, the required files are [here](assets). All credit goes to david942j for creating the challenge.

## Context

We're told to connect to a server using netcat:

```bash
nc 52.192.42.xxx 9427
```

We're also given a ruby script by the name of [server.rb](assets/server.rb), presumably the script running on the server we're going to be connecting to, and a mysterious [time_machine](assets/time_machine).

Connecting to the server as instructed, we're prompted for the size of some shellcode:

```
Size of shellcode? (MAX: 2000)
0
ಠ_ಠ
```

Oh, let's try that again with a non-zero number. We're then prompted to enter however many bytes we gave as a size:

```
Size of shellcode? (MAX: 2000)
1
Reading 1 bytes..
A
Shellcode receieved. Launching Time Machine..
Failed - Child dead unexpectedly.
```

It looks like the time machine might be what's running our shellcode. In any case, let's get reversing to figure out what our shellcode needs to do!

## server.rb

The ruby script is fairly straightforward. The main bits we need to are these:

```ruby
PG_SZ = 0x1000
RX = 0xdead0000
RW = 0x02170000

# ...

def prepare_sc
  "\xEBZj&_j\x01^1\xC0\xB0\x9D\x0F\x05j\x16_H\x8D\x15\x14\x00\x00\x00Rj\x06H\x89\xE2j\x02^1\xC0\xB0\x9D\x0F\x05H\x83\xC4\x10\xC3 \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x02>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\v\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\xE8\xA1\xFF\xFF\xFFH\x89\xE7H\x81\xE7\x00\xF0\xFF\xFFH\x81\xEF\x00\x10\x02\x00H\xC7\xC6\x00@\x02\x00H1\xC0\xB0\v\x0F\x05"
end

def main
  puts "Size of shellcode? (MAX: 2000)"
  len = gets.to_i
  return puts "ಠ_ಠ" if len <= 0 || len > 2000
  puts "Reading #{len} bytes.."
  sc = STDIN.read(len)
  return puts "EOF" if sc.size != len
  path = make_elf(prepare_sc + sc)
  puts "Shellcode receieved. Launching Time Machine.."
  sleep(1)
  Process.exec(File.join(__dir__, "time_machine"), path)
end 
```

We can see that the `main` function reads our shellcode, appends it to some preparation shellcode and creates an ELF executable with the result. It then calls the time machine with the newly built ELF as the only argument.

Constants at the top tell us that the ELF maps a readable and executable memory page at `0xdead0000` — for the code — along with a readable and writable page at `0x2170000`. The code I omitted is all the boilerplate that builds the ELF; examining it confirms that there's no trickery involved.

We also note that the preparation shellcode is 128 bytes long, so while the RX memory page starts at `0xdead0000`, our own shellcode will start at `0xdead0080`.

### Preparation shellcode

So what does this opaque binary blob that's prepended to our own shellcode do? Disassembling it yields something like this, after a little manual clean-up, using nasm syntax:

```asm
    bits 64

    jmp start

protect:
    ; make sure we don't gain new privileges
    push 0x26
    pop rdi         ; PR_SET_NO_NEW_PRIVS
    push 0x1
    pop rsi
    xor eax, eax
    mov al, 0x9d    ; prctl
    syscall

    ; filter syscalls
    push 0x16
    pop rdi                 ; PR_SET_SECCOMP
    lea rdx, [rel filters]
    push rdx                ; sock filters
    push 0x6                ; number of sock filters
    mov rdx, rsp            ; BPF (sock_fprog)
    push 0x2
    pop rsi                 ; SECCOMP_MODE_FILTER
    xor eax, eax
    mov al, 0x9d            ; prctl
    syscall

    add rsp, 0x10
    ret

filters:
    db 0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x02, 0x3e, 0x00, 0x00, 0xc0, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f

start:
    call protect

    ; unmap the stack
    mov rdi, rsp                ; get current stack pointer
    and rdi, 0xfffffffffffff000 ; adjust for page alignment
    sub rdi, 0x21000            ; calculate an address range
    mov rsi, 0x24000            ;   should cover the whole stack
    xor rax, rax
    mov al, 0xb                 ; unmap
    syscall
```

In short, it makes sure we won't be able to gain privileges, perform syscalls or use the stack. Neat!

## time_machine

Now let's move on to the time machine and fire up Ghidra. Looking around a little, we can easily locate the main function, which looks like this in the decompiler:

```c
undefined8 FUN_001012fa(int param_1,long param_2)
{
  bool bVar1;
  bool bVar2;
  int iVar3;
  char cVar4;
  long lVar5;
  undefined8 uVar6;
  long in_FS_OFFSET;
  uint local_2c;
  uint local_28;
  uint local_24;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 != 2) {
                    /* WARNING: Subroutine does not return */
    exit(2);
  }
  setbuf(stdout,(char *)0x0);
  DAT_00302040 = fork();
  if (DAT_00302040 == 0) {
    ptrace(PTRACE_TRACEME,0,0,0);
    execve(*(char **)(param_2 + 8),(char **)0x0,(char **)0x0);
    FUN_00100c97("execve");
  }
  lVar5 = ptrace(PTRACE_ATTACH,(ulong)DAT_00302040,0,0);
  if (lVar5 != 0) {
    err(1,"ptrace");
  }
  local_2c = 0;
  local_28 = waitpid(DAT_00302040,(int *)&local_2c,2);
  if ((local_28 != DAT_00302040) || ((local_2c & 0xff) != 0x7f)) {
    FUN_00100c97("the first wait");
  }
  bVar1 = false;
  bVar2 = false;
  while( true ) {
    do {
      lVar5 = ptrace(PTRACE_SINGLESTEP,(ulong)DAT_00302040,0,0);
      if (lVar5 != 0) {
        err(1);
      }
      local_28 = wait(&local_2c);
      if ((local_2c & 0x7f) == 0) goto LAB_00101558;
      local_24 = (int)local_2c >> 8 & 0xff;
      if (local_24 != 5) {
        FUN_00100c66("Child dead unexpectedly.");
      }
      if (0xfff < DAT_00302044) {
        FUN_00100c66("Too many steps.");
      }
      if (!bVar1) {
        lVar5 = FUN_00100e73();
        if (lVar5 == 0xdead0080) {
          bVar1 = true;
          FUN_0010127a();
          FUN_00100b39();
          FUN_00100ada();
          FUN_00101128();
        }
      }
    } while (!bVar1);
    cVar4 = FUN_00101281();
    iVar3 = DAT_00302044;
    if (cVar4 != '\0') break;
    DAT_00302044 = DAT_00302044 + 1;
    uVar6 = FUN_00100e73();
    *(undefined8 *)(&DAT_00302060 + (long)iVar3 * 8) = uVar6;
  }
  bVar2 = true;
LAB_00101558:
  if (!bVar2) {
    FUN_00100c66(&DAT_00101731);
  }
  cVar4 = FUN_001011c7();
  if (cVar4 != '\x01') {
    FUN_00100c66("Please swallow the cookie.");
  }
  FUN_00100cc8();
  cVar4 = FUN_0010121e();
  if (cVar4 != '\x01') {
    FUN_00100c66("You should vomit the cookie out.");
  }
  FUN_0010125b();
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

It's a little messy, so let's clean up the obvious and remove the unnecessary:

```c
int main(int argc,char **argv)
{
    if (argc != 2) {
        exit(2);
    }
    setbuf(stdout, 0);

    // Launch argv[1] and attach to it with ptrace.
    PID = fork();
    if (PID == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execve(argv[1], 0, 0);
        fail_contact_admin("execve");
    }
    if (ptrace(PTRACE_ATTACH, PID, 0, 0)) {
        err(1, "ptrace");
    }
    int status = 0;
    pid_t pid = waitpid(PID, &status, 2);
    if ((pid != PID) || ((status & 0xff) != 0x7f)) {
        fail_contact_admin("the first wait");
    }

    // Step through the child process.
    bool reached_shellcode = false;
    while (true) {
        if (ptrace(PTRACE_SINGLESTEP, PID, 0, 0 )) {
            err(1);
        }

        // Make sure the child is still running.
        wait(&status);
        if ((status & 0x7f) == 0) {
            fail("...?")
        }
        if ((status >> 8 & 0xff) != 5) {
            fail("Child dead unexpectedly.");
        }

        if (0xfff < STEPS) {
            fail("Too many steps.");
        }

        // Initialization when reaching our shellcode.
        if (!reached_shellcode && get_rip() == 0xdead0080) {
            reached_shellcode = true;
            noop();
            FUN_00100b39();
            FUN_00100ada();
            FUN_00101128();
        }

        // Record instruction pointer and check for exit condition.
        if (reached_shellcode) {
            int current_step = STEPS;
            if (should_exit()) break;
            STEPS = STEPS + 1;
            RIPS[current_step] = get_rip();
        }
    }

    if (!did_swallow_cookie()) {
        fail("Please swallow the cookie.");
    }
    FUN_00100cc8();
    if (!did_vomit_cookie()) {
        fail("You should vomit the cookie out.");
    }

    // Win!
    print_flag();

    return 0;
}
```

The only part of the refactoring so far that perhaps doesn't look exactly trivial is naming the `get_rip` function (formerly `FUN_00100e73`), which in turn helped name the `reached_shellcode` and `RIPS` variables and organize the code using those. But it's easy to assume its behavior (returning the current instruction pointer of the child process) when looking at the comparison with `0xdead0080` which is the start of our shellcode. We can verify that assumption by examining the function which, after a bit of clean up, looks like this:

```c
long get_rip()
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }
    return regs.rip;
}
```

So we're now starting to paint a decent picture of what this time machine is doing... except I still don't see any time travel. The gist of what we know so far is that the time machine performs some initialization, then steps through our shellcode a maximum of 4096 times, waiting for some exit condition and recording the instruction pointer at every step in an array. During this process, our shellcode needs to *swallow some cookie* — whatever that means. Then, `FUN_00100cc8` runs and that process must *vomit the cookie out* — again, whatever that means — which sounds like it may be the time travel part. And if we succeed at that, we win and get the flag!

So let's first look at the two checks for the cookie ingestion and regurgitation to figure out what exactly our objective is. Then we'll check out the initialization process and the exit condition for the main loop (the `should_exit` method above) to find out how we'll go about swallowing the cookie. Finally, we'll look at `FUN_00100cc8` to see how the time machine will interact with our shellcode to vomit the cookie out.

### What's this cookie business?

Alright, we'll start with `did_swallow_cookie` to see what swallowing the cookie means. The cleaned-up version looks like this:

```c
bool did_swallow_cookie()
{
  long bits_set = 0;
  for (unsigned long addr = 0x2170000; addr < 0x2171000; addr += 8) {
    bits_set |= ptrace(PTRACE_PEEKDATA, PID, addr, 0);
  }
  return bits_set == 0;
}
```

So it looks like the cookie is what's in the RW memory page and swallowing it means clearing it. Now what about vomitting it out? Let's see:

```c
bool did_vomit_cookie()
{
  long cookie = ptrace(PTRACE_PEEKDATA, PID, 0x2170000, 0);
  return cookie == COOKIE;
}
```

Okay, so the first 8 bytes of the same memory page are compared against a value in static memory, so I suppose that means the cookie is really just the first 8 bytes. Presumably, this means that our shellcode will need to read those 8 bytes and clear them in the main loop we analyzed earlier, then restore it in `FUN_00100cc8`.

### Initialization process

We have three functions to look at to understand the initialization that happens before our shellcode runs: `FUN_00100b39`, `FUN_00100ada` and `FUN_00101128`. They're all pretty straightforward, we'll go through them in order.

The first one, which we'll rename to `reset_registers`, uses ptrace to set all registers to zero except for `rip` which is set to `0xdead0080` (the beginning of our shellcode), `cs` which is set to `0x33` and `ss` which is set to `0x2b`. It boils down to this:

```c
void reset_registers() {
    struct user_regs_struct regs;
    memset(regs, 0, sizeof(regs));
    regs.rip = 0xdead0080;
    regs.cs = 0x33;
    regs.ss = 0x2b;
    if (ptrace(PTRACE_SETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }

    struct user_fpregs_struct fpregs;
    memset(fpregs, 0, sizeof(fpregs));
    if (ptrace(PTRACE_SETFPREGS, PID, 0, &fpregs)) {
        err(1, "ptrace");
    }
}
```

The second one clears the RW memory page, so we'll call it `clear_memory`:

```c
void clear_memory() {
    for (unsigned long addr = 0x2170000; addr < 0x2170000; addr += 8) {
        if (ptrace(PTRACE_POKEDATA, PID, addr, 0)) {
            err(1, "ptrace");
        }
    }
}
```

And finally the last one generates 8 random bytes for the cookie, stores it in static memory for the comparison later in `did_vomit_cookie` and also writes it at the beginning of the RW memory page:

```c
void init_cookie() {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fail_contact_admin("open urandom");
    }
    if (read(fd, &COOKIE, 8) != 8) {
        fail_contact_admin("read urandom");
    }
    if (ptrace(PTRACE_POKEDATA, PID, 0x2170000, COOKIE)) {
        err(1, "ptrace");
    }
}
```

So the initialization step is simple: it clears all registers, writes the cookie at `0x2170000` and clears the rest of this memory page.

### Get me out of this loop

Earlier, we labeled a function `should_exit`, because it's clearly the exit condition for the main loop in the `main` function. Now, we need to look at it to figure out what exactly that exit condition is. This function references three other functions though, so we'll first look at those.

`FUN_00100ee8` becomes `is_syscall` because it returns whether or not the current instruction is `syscall` (or `sysenter`) and if so, sets its argument to the syscall number.

```c
bool is_syscall(unsigned long *syscall_number) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }

    // Check if the current opcode (in little endian) is
    // 0x50f for syscall or 0x340f for sysenter.
    unsigned long opcode = ptrace(PTRACE_PEEKDATA, PID, regs.rip, 0);
    if ((opcode & 0xffff) == 0x50f || (opcode & 0xffff) == 0x340f) {
        // This is a syscall, the syscall number is stored in rax.
        *syscall_number = regs.rax;
        return true;
    }

    return false;
}
```

`FUN_00100fc8` becomes `invalid_segments` because it returns whether or not the `cs` and `ss` registers have changed:

```c
bool invalid_segments() {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }
    return !(regs.cs == 0x33 && regs.ss == 0x2b);
}
```

And finally, `FUN_0010105c` becomes `increment_rip` because it adds the given value to the instruction pointer:

```c
void increment_rip(long increment) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }
    regs.rip += increment;
    if (ptrace(PTRACE_SETREGS, PID, 0, &regs)) {
        err(1, "ptrace");
    }
}
```

With an understanding of those three functions, `should_exit` becomes straightforward:

```c
bool should_exit() {
    long syscall_number;
    while (is_syscall(&syscall_number)) {
        // If the current instruction is an exit syscall, return true.
        if (syscall_number == 60) {
            return true;
        }
        // Skip all other syscalls.
        increment_rip(2);
    }
    if (invalid_segments()) {
        fail("NO.");
    }
    return false;
}
```

So our exit condition is an exit syscall, that makes sense! But this function, which is called at each step of the execution of our shellcode, also skips all other syscall instructions and makes sure we're not trying to mess with the `cs` and `ss` registers.

### Travelling in time

We now have one last function (`FUN_00100cc8`) to reverse engineer in order to get the complete picture of this time machine. And since we haven't seen any time travelling so far, this is where it happens, right? Right!

As a quick reminder, this function is called after our shellcode has finished executing (well, after the exit syscall anyway) and the cookie has been checked to be cleared, and before the cookie is checked to be back in memory.

This function is relatively simple:

```c
void go_back() {
    reset_registers();
    int current_step = STEPS;
    while (true) {
        if (--current_step < 0) return;

        // Pop a value from the end of RIPS and use it to update the instruction pointer.
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, PID, 0, &regs)) {
            err(1, "ptrace");
        }
        regs.rip = RIPS[current_step];
        if (ptrace(PTRACE_SETREGS, PID, 0, &regs)) {
            err(1, "ptrace");
        }

        // Execute the instruction at the address that was just popped.
        if (ptrace(PTRACE_SINGLESTEP, PID, 0, 0)) {
            err(1, "ptrace");
        }

        // Make sure everything's still running properly.
        int status;
        wait(&status);
        if ((status & 0x7f) == 0) break;
        if (status >> 8 & 0xff != 5) {
            fail("Child dead..");
        }
    }
    puts("exit too early..");
    exit(1);
}
```

Ah, so the array that was used to record the instruction pointer at every step before is now used as a stack to execute those same instructions again, but in reverse order. That does sound like time travel!

## Objective recap

Let's take a moment to summarize what our goal here is.

We need to write some shellcode no longer than 2000 bytes that, when executed normally (the forward pass), will clear a 4096-byte memory page at `0x2170000` in no more than 4096 steps, then executes an exit syscall. Thankfully, only the first 8 bytes of the page will be non-zero — the so-called cookie.

Then, registers will be cleared with ptrace and instructions from the forward pass will be executed in reverse order. This backward pass must restore the cookie in the first 8 bytes of the same memory page to its initial value.

Importantly, we do *not* have access to the stack or any other read-writable memory in which we could store the cookie between the two passes.

## The birth of an idea

When confronted with this challenge, some other participants [[1](https://github.com/Pusty/writeups/blob/master/HITCONCTF2020/README.md#tenet), [2](https://github.com/FrenchRoomba/ctf-writeup-HITCON-CTF-2020/tree/master/tenet)] noticed that they could use the AVX registers to store the cookie, since only their lowest 128 bits are cleared between the two passes. This would've been relatively straightforward, but my mind went in a completely different direction, so buckle up!

Instead of noticing what's implicitly preserved between the two passes by virtue of not being cleared properly (i.e. the AVX registers), I focused on what is *explicitly* preserved: the instruction stack. What if we could encode the cookie in the executed instructions themselves?

The key thing to realize here is that the time machine doesn't really run our shellcode itself backward. Rather, it really only re-runs instructions executed in the forward pass, but in reverse order. This means that all the control flow for the backward pass is determined by the forward pass. So the forward pass can jump around to instructions that *themselves* directly encode the cookie and the backward pass will then execute those same instructions to decode the cookie in reverse order. And all of the jump instructions used in the forward pass will have no effect at all during the backward pass.

## Solution

So the idea sounds promising, but it's still pretty abstract. Let's see now how it can be implemented.

The most basic implementation of this idea would be to have a sort of jump table with an entry for each possible value of the cookie. Each entry would load the appropriate value, then jump back to some common code. Ignoring some issues like entries having different lengths, it would look something like this:

```asm
    bits 64

start:
    mov rdi, [0x2170000]
    lea rdi, [table + rdi * ENTRY_SIZE]
    jmp rdi
continue:
    mov rax, 60
    syscall

table:
    mov qword [0x2170000], rax
    mov rax, 0x0000000000000001
    jmp continue
    mov qword [0x2170000], rax
    mov rax, 0x0000000000000002
    jmp continue
    mov qword [0x2170000], rax
    mov rax, 0x0000000000000003
    jmp continue
    ; ...
    mov qword [0x2170000], rax
    mov rax, 0xffffffffffffffff
    jmp continue
```

Now, of course this is actually impossible to implement: we would need 2<sup>64</sup> entries in the table. So maybe we could do it one byte at a time? That would require 256 entries, which would each need to be at most 7 bytes long to respect the limit of 2000 bytes. Add to that that we wouldn't be able to use short jumps for all entries and might have to deal with padding to make sure all entries are the same size... we would be cutting it close. So then one nibble at a time? With only 16 entries required, size constraints definitely wouldn't be a problem. That sounds like a good plan!

Working with nibbles brings an additional consideration, however. Using `mov` instructions like we showed above only works on whole bytes, so we have to be careful not to overwrite the cookie as we're traversing it. The solution for this is simple though: use the `or` instruction. On the forward pass, that will leave the cookie unchanged because we'll be `or`'ing it with itself and some zeros. And on the backward pass, it will restore the cookie as required since we'll be `or`'ing zeros with nibbles of the cookie.

Also, to keep the logic a bit simpler and since we have more than enough space to work with, we can implement two distinct jumping tables: one for the high nibbles and one for the low nibbles.

So putting this all together, we get something like this:

```asm
    bits 64

start:
    mov rax, 0x2170000  ; keep the address of the cookie handy for the forward pass
    mov rbp, 0xdead0080 ; we'll also need the start address of our code to calculate offsets

    ; initialization for the forward pass
    mov rsi, 1      ; used to increment the loop index at each iteration on the forward pass
    ; rcx = 0       ; loop index starts at 0 for the forward pass (set by the time machine)
    ; rdx = 0       ; used to store the rcx'th byte of the cookie (set by the time machine)

; main loop
; on the forward pass, this calculates offsets into the jump tables below (hitable & lotable) based on
;    the value of the cookie, one nibble at a time, from lowest to highest address
;    the 'or' instructions in the jump tables are essentially noops, since they or the cookie with itself
; on the backward pass, the only instruction that matters is 'add rcx, rsi', at the very end of the loop
;    it is used to moved from the highest to the lowest nibble, so that instructions from the jump tables,
;    which is executed in reverse order by virtue of being in the instruction stack, affect the
;    correct bytes
;    the 'or' instructions in the jump tables, this time, restore the value of the cookie, since they or
;    the currently zeroed cookie with its initial value
loop:
    mov byte dl, [rax + rcx]        ; read the rcx'th byte of the cookie
    shr rdx, 4                      ; shift the high nibble into the low nibble
    mov rdi, rdx                    ; calculate offset to jump to in hitable
    lea rdi, [2 * rdi]              ;   that will set the high nibble of the
    lea rdi, [3 * rdi]              ;   cookie's rcx'th byte to the value of rdx:
    lea rdi, [rbp + hitable + rdi]  ;   rdi = 6 * rdx + hitable + 0xdead0080
    jmp rdi                         ; jump to the calculated offset
hiret:                              ; after setting the high nibble of the cookie, jump back here
    mov byte dl, [rax + rcx]        ; read the rcx'th byte of the cookie, again
    and dl, 0x0F                    ; only keep the low nibble
    mov rdi, rdx                    ; calculate offset to jump to in lotable
    lea rdi, [2 * rdi]              ;   that will set the low nibble of the
    lea rdi, [3 * rdi]              ;   cookie's rcx'th byte to the value of rdx:
    lea rdi, [rbp + lotable + rdi]  ;   rdi = 6 * rdx + lotable + 0xdead0080
    jmp rdi                         ; jump to the calculated offset
loret:                              ; after setting the low nibble of the cookie, jump back here
    add rcx, rsi    ; increment rcx on the forward pass, decrement it on the backward pass
    cmp rcx, 0x8    ; exit condition for the forward pass
    jne loop        ; has no effect on the backward pass

    ; initialization for the backward pass
    mov rcx, 0x8    ; loop index starts at 8 for the forward pass
    mov rsi, -1     ; used to decrement the loop index at each iteration on the forward pass

    mov qword [rax], 0  ; clear the cookie, as required on the forward pass
    mov rax, 0x2170000  ; keep the address of the cookie handy for the backward pass

    mov rax, 60         ; signal the end of the forward pass
    syscall             ;   with the exit syscall

; jump table used to restore high nibbles of the cookie
hitable:
    or byte [rax + rcx], 0x00
    jmp hinext
    or byte [rax + rcx], 0x10
    jmp hinext
    or byte [rax + rcx], 0x20
    jmp hinext
    or byte [rax + rcx], 0x30
    jmp hinext
    or byte [rax + rcx], 0x40
    jmp hinext
    or byte [rax + rcx], 0x50
    jmp hinext
    or byte [rax + rcx], 0x60
    jmp hinext
    or byte [rax + rcx], 0x70
    jmp hinext
    or byte [rax + rcx], 0x80
    jmp hinext
    or byte [rax + rcx], 0x90
    jmp hinext
    or byte [rax + rcx], 0xA0
    jmp hinext
    or byte [rax + rcx], 0xB0
    jmp hinext
    or byte [rax + rcx], 0xC0
    jmp hinext
    or byte [rax + rcx], 0xD0
    jmp hinext
    or byte [rax + rcx], 0xE0
    jmp hinext
    or byte [rax + rcx], 0xF0
    jmp hinext
hinext:                     ; make all table entries jump here rather then directly to hiret
    jmp hiret               ;   to ensure that all entries have the same length (6 bytes)

; jump table used to restore low nibbles of the cookie
lotable:
    or byte [rax + rcx], 0x00
    jmp lonext
    or byte [rax + rcx], 0x01
    jmp lonext
    or byte [rax + rcx], 0x02
    jmp lonext
    or byte [rax + rcx], 0x03
    jmp lonext
    or byte [rax + rcx], 0x04
    jmp lonext
    or byte [rax + rcx], 0x05
    jmp lonext
    or byte [rax + rcx], 0x06
    jmp lonext
    or byte [rax + rcx], 0x07
    jmp lonext
    or byte [rax + rcx], 0x08
    jmp lonext
    or byte [rax + rcx], 0x09
    jmp lonext
    or byte [rax + rcx], 0x0A
    jmp lonext
    or byte [rax + rcx], 0x0B
    jmp lonext
    or byte [rax + rcx], 0x0C
    jmp lonext
    or byte [rax + rcx], 0x0D
    jmp lonext
    or byte [rax + rcx], 0x0E
    jmp lonext
    or byte [rax + rcx], 0x0F
    jmp lonext
lonext:                     ; make all table entries jump here rather then directly to loret
    jmp loret               ;   to ensure that all entries have the same length (6 bytes)
```

### Validation through tracing

To better understand how this mind-bending program works, or to actually convince ourselves that it *might* work, let's partially trace the execution of this code with a (not so) random cookie: `[0x12, 0x90, 0x34, 0x78, 0x10, 0x29, 0x38, 0x47]`. Let's start with the forward pass:

```asm
mov rax, 0x2170000  ; rax = 0x2170000
mov rbp, 0xdead0080 ; rbp = 0xdead0080

; initialization for the loop
mov rsi, 1      ; rsi = 1 (rcx = 0, rdx = 0)

; first iteration of the main loop

; handling the high nibble of cookie[0]
mov byte dl, [rax + rcx]        ; rdx = cookie[0] = 0x12
shr rdx, 4                      ; rdx = 0x01 = 1
mov rdi, rdx                    ; rdi = 1
lea rdi, [2 * rdi]              ; rdi = 2
lea rdi, [3 * rdi]              ; rdi = 6
lea rdi, [rbp + hitable + rdi]  ; rdi = hitable + 6, with each table entry being 6 bytes,
jmp rdi                         ;   this is conceptually hitable[1]
; in the high nibble jump table
or byte [rax + rcx], 0x10       ; cookie[0] |= 0x10 => cookie[0] = 0x12 (no change)
jmp hinext
jmp hiret

; handling the low nibble of cookie[0]
mov byte dl, [rax + rcx]        ; rdx = cookie[0] = 0x12
and dl, 0x0F                    ; rdx = 0x02 = 2
mov rdi, rdx                    ; rdi = 2
lea rdi, [2 * rdi]              ; rdi = 4
lea rdi, [3 * rdi]              ; rdi = 12
lea rdi, [rbp + lotable + rdi]  ; rdi = lotable + 12, with each table entry being 6 bytes,
jmp rdi                         ;   this is conceptually lotable[2]
; in the low nibble jump table
or byte [rax + rcx], 0x02       ; cookie[0] |= 0x02 => cookie[0] = 0x12 (no change)
jmp lonext
jmp loret

add rcx, rsi    ; rcx += 1 => rcx = 1
cmp rcx, 0x8
jne loop        ; keep iterating

; ...

; eighth iteration of the main loop (rcx = 7)

; handling the high nibble of cookie[7]
mov byte dl, [rax + rcx]        ; rdx = cookie[7] = 0x47
shr rdx, 4                      ; rdx = 0x04 = 4
mov rdi, rdx                    ; rdi = 4
lea rdi, [2 * rdi]              ; rdi = 8
lea rdi, [3 * rdi]              ; rdi = 24
lea rdi, [rbp + hitable + rdi]  ; rdi = hitable + 24, with each table entry being 6 bytes,
jmp rdi                         ;   this is conceptually hitable[4]
; in the high nibble jump table
or byte [rax + rcx], 0x40       ; cookie[7] |= 0x40 => cookie[7] = 0x47 (no change)
jmp hinext
jmp hiret

; handling the low nibble of cookie[7]
mov byte dl, [rax + rcx]        ; rdx = cookie[7] = 0x47
and dl, 0x0F                    ; rdx = 0x07 = 7
mov rdi, rdx                    ; rdi = 7
lea rdi, [2 * rdi]              ; rdi = 14
lea rdi, [3 * rdi]              ; rdi = 42
lea rdi, [rbp + lotable + rdi]  ; rdi = lotable + 42, with each table entry being 6 bytes,
jmp rdi                         ;   this is conceptually lotable[7]
; in the low nibble jump table
or byte [rax + rcx], 0x07       ; cookie[7] |= 0x07 => cookie[7] = 0x47 (no change)
jmp lonext
jmp loret

add rcx, rsi    ; rcx += 1 => rcx = 8
cmp rcx, 0x8
jne loop        ; stop iterating

; initialization for the backward pass
mov rcx, 0x8    ; rcx = 8 (not used anymore)
mov rsi, -1     ; rsi = -1 (not used anymore)

mov qword [rax], 0  ; cookie = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
mov rax, 0x2170000  ; rax = 0x2170000 (overwritten with the next instruction)

mov rax, 60         ; rax = 60
syscall             ; we're done
```

The forward pass seems fine, it jumps around the two jump tables based on the value of the cookie and then clears the cookie. But what about the backward pass? Let's reverse this trace and see:

```asm
mov rax, 60         ; rax = 60 (overwritten with the next instruction)

mov rax, 0x2170000  ; rax = 0x2170000
mov qword [rax], 0  ; cookie = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

; initialization for the backward pass
mov rsi, -1     ; rsi = -1
mov rcx, 0x8    ; rcx = 8

; first iteration of the main loop

jne loop        ; no effect
cmp rcx, 0x8    ; not used
add rcx, rsi    ; rcx += -1 => rcx = 7

; handling the low nibble of cookie[7]
; in the low nibble jump table
jmp loret                       ; no effect
jmp lonext                      ; no effect
or byte [rax + rcx], 0x07       ; cookie[7] |= 0x07 => cookie[7] = 0x07
; back to the main loop
jmp rdi                         ; no effect
lea rdi, [rbp + lotable + rdi]  ; rdi = ? (not used)
lea rdi, [3 * rdi]              ; rdi = ? (not used)
lea rdi, [2 * rdi]              ; rdi = ? (not used)
mov rdi, rdx                    ; rdi = ? (not used)
and dl, 0x0F                    ; rdx = ? (not used)
mov byte dl, [rax + rcx]        ; rdx = cookie[7] = 0x07 (not used)

; handling the high nibble of cookie[7]
; in the high nibble jump table
jmp hiret                       ; no effect
jmp hinext                      ; no effect
or byte [rax + rcx], 0x40       ; cookie[7] |= 0x40 => cookie[7] = 0x47
; back to the main loop
jmp rdi                         ; no effect
lea rdi, [rbp + hitable + rdi]  ; rdi = ? (not used)
lea rdi, [3 * rdi]              ; rdi = ? (not used)
lea rdi, [2 * rdi]              ; rdi = ? (not used)
mov rdi, rdx                    ; rdi = ? (not used)
shr rdx, 4                      ; rdx = ? (not used)
mov byte dl, [rax + rcx]        ; rdx = cookie[7] = 0x47 (not used)

; ...

; eighth iteration of the main loop (rcx = 1)

jne loop        ; no effect
cmp rcx, 0x8    ; not used
add rcx, rsi    ; rcx += -1 => rcx = 0

; handling the low nibble of cookie[0]
; in the low nibble jump table
jmp loret                       ; no effect
jmp lonext                      ; no effect
or byte [rax + rcx], 0x02       ; cookie[0] |= 0x02 => cookie[0] = 0x02
; back to the main loop
jmp rdi                         ; no effect
lea rdi, [rbp + lotable + rdi]  ; rdi = ? (not used)
lea rdi, [3 * rdi]              ; rdi = ? (not used)
lea rdi, [2 * rdi]              ; rdi = ? (not used)
mov rdi, rdx                    ; rdi = ? (not used)
and dl, 0x0F                    ; rdx = ? (not used)
mov byte dl, [rax + rcx]        ; rdx = cookie[0] = 0x02

; handling the high nibble of cookie[0]
; in the high nibble jump table
jmp hiret                       ; no effect
jmp hinext                      ; no effect
or byte [rax + rcx], 0x10       ; cookie[0] |= 0x10 => cookie[0] = 0x12
; back to the main loop
jmp rdi                         ; no effect
lea rdi, [rbp + hitable + rdi]  ; rdi = ? (not used)
lea rdi, [3 * rdi]              ; rdi = ? (not used)
lea rdi, [2 * rdi]              ; rdi = ? (not used)
mov rdi, rdx                    ; rdi = ? (not used)
shr rdx, 4                      ; rdx = ? (not used)
mov byte dl, [rax + rcx]        ; rdx = cookie[0] = 0x12

; initialization for the loop
mov rsi, 1      ; rsi = 1 (not used)

mov rbp, 0xdead0080 ; rbp = 0xdead0080 (not used)
mov rax, 0x2170000  ; rax = 0x2170000 (not used anymore)
```

It looks like the backward pass does restore the cookie one nibble at a time, so it should work!

### Getting the flag

All that's left at this point, is to run our shellcode against the server and ~~hope for the best~~ confidently wait for the flag:

```bash
$ nasm shellcode.s && cat <(wc -c shellcode | cut -d' ' -f1) shellcode | nc 52.192.42.xxx 9427
Size of shellcode? (MAX: 2000)
Reading 312 bytes..
Shellcode receieved. Launching Time Machine..
Perfect.
hitcon{whats happened happened, this is the mechanism of the world}
```

Success!
