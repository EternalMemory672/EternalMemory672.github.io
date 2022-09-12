整体思路：
1.qemu+gdb的调试环境。2.驱动（.ko文件）逆向，漏洞发现。3.利用给你的驱动中的漏洞在用户态写 .c 文件，静态编译，然后qemu启动内核去打。4.攻击目标一般是提权，比较朴素的是想方设法调用：commit\_creds(prepare\_kernel\_cred(0))
具体思路：
1. 运行发现两分钟强制关机，解包删除init中的自动关机指令，打包，重新运行
2. /tmp下有系统符号表，打开找commit\_creds、prepare\_kernel\_cred两个函数的地址
3. 在解包中找到core.ko应为漏洞驱动，checksec检查，拷出并IDA反编译