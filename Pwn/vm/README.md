# vm writeup

- ubuntu 18.04
- c++编写的字节码解释器，定义了一个虚拟的栈结构，有8个常规寄存器以及rsp、rbp、rip三个特殊寄存器。定义并实现了虚拟的栈空间上的push, pop, mov, add, call, ret, jmp等操作，读入0x1000长度的字节码，进行命令的合法性和安全性检查，最后运行命令
- 在安全性检查中主要对栈操作的边界进行了检查，防止越界的栈操作。在检查中遇到jmp命令没有进行跳转，可以用类似`jmp $+4; push r[0]; pop r[0]`的方式绕过安全性检查实现越界读写。
- 栈空间分布在堆上，call和ret命令可以进行malloc和free。
- 存在一个seccomp沙箱，只允许read, open, exit, exit_group四项系统调用，需要侧信道爆破flag。我们写ROP进行侧信道，open read读取flag之后进行逐字节比较，比较成功（或失败）时调用read阻塞，通过p.recv(1,timeout=2)和EOFError信号判断是否比较成功。
- libc中的environ变量可以获取栈地址，通过命令集中的`mov qword ptr[reg1],reg2`实现任意地址写进行ROP。