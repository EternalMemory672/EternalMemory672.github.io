## 反弹shell
#反弹shell
伪shell->shell
有python环境
```shell
python -c "import pty; pty.spawn('/bin/bash')"
```