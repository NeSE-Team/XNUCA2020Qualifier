# ParseC writeup

- 类C代码解释器
	- `./ParseC example`
- 实现了基本的数学运算和C语法。支持char、Array、double、string四个变量，支持函数定义，支持puts(str)、print(double)、read(double)三个自带函数。
- 漏洞是对string变量的引用计数问题，string变量内容存储在堆上，在对两个字符串变量`a=b`进行赋值操作时，直接将堆指针进行了复制，使a,b的指针指向同一个地址，释放掉b的指针后造成了UAF。
- free存在于对string变量的重新赋值操作中。
- malloc存在于string变量和array变量的定义操作中。
- 泄露libc地址后通过自带的read(double)函数进行写操作覆盖free\_hook，需要进行双精度浮点数的转换。
- UAF劫持tcache后，覆盖free\_hook的方法有多种。
	- 定义array变量malloc到free\_hook附近，通过类似`read(array[i])`的方式覆盖free\_hook
	- `read("aaaaaaaaa")`，解析时会将aaaaaaa字符串malloc到free\_hook附近，然后进行read。这种方法在read之后会因为语法错误退出，退出时调用了`free(code)`，因此只需要提前在代码文件第一行写注释`//bin/sh`即可getshell。

