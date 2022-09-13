#nohup 
进程不挂断 &后台运行
```shell
nohup ../jdk1.8/bin/java -jar ./Behinder.jar >/dev/null 2>&1 &
```
`ls ../`读取上一级目录

==cd file?../../../ 为访问上级目录==
[[|Lang/PHP/function&class/include]]

**#sudo vim /etc/ssh/sshd_config**

找到并用#注释掉这行：PermitRootLogin prohibit-password

/usr/local/nginx/conf

openssh-server
ssh-keygen -R “你的远程服务器ip地址”