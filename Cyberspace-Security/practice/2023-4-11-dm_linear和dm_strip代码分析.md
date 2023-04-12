# 2023-4-11-dm_linear和dm_strip代码分析

Early creation of mapped devices

```
dm-mod.create=<name>,<uuid>,<minor>,<flags>,<table>[,<table>+][;<name>,<uuid>,<minor>,<flags>,<table>[,<table>+]+]
<name>          ::= The device name.
<uuid>          ::= xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | ""
<minor>         ::= The device minor number | ""
<flags>         ::= "ro" | "rw"
<table>         ::= <start_sector> <num_sectors> <target_type> <target_args>
<target_type>   ::= "verity" | "linear" | ... (see list below)
```

linear

```
dm-linear,,,rw,
  0 32768 linear /dev/sda1 0,
  32768 1024000 linear /dev/sda2 0,
  1056768 204800 linear /dev/sda3 0,
  1261568 512000 linear /dev/sda4 0
===
name = dm-linear
uuid = 
minor = 
flag = rw
table = 
	start_sector = 0
    num_sector = 32768
    target_type = linear
    target_args = /dev/sda1 0
table = 32768 1024000 linear /dev/sda2 0
table = 1056768 204800 linear /dev/sda3 0
table = 1261568 512000 linear /dev/sda4 0
```



striped

```
dm-striped,,4,ro,
0 1638400 striped 
4 4096 
/dev/sda1 0 
/dev/sda2 0 
/dev/sda3 0 
/dev/sda4 0
===
name = dm-striped
uuid = 
minor = 4
flag = ro
table = 0 1638400 striped 4 4096
table = 32768 1024000 linear /dev/sda2 0
table = 1056768 204800 linear /dev/sda3 0
table = 1261568 512000 linear /dev/sda4 0
```



