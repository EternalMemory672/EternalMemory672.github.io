## Horizontall
### 信息收集
![[../attaches/Pasted image 20220119192438.png]]
访问之后发现页面直接跳转，将10.10.11.105加入到host文件中，在horizontall.htb中进行扫描，发现在其中一个js文件中存在一个子域名：api-prod.horizontall.htb，使用dirsearch对其进行扫描如下：
```shell
[11:28:47] 400 -   67B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[11:28:56] 200 -  854B  - /admin                                            
[11:28:56] 200 -  854B  - /ADMIN                                            
[11:28:56] 200 -  854B  - /Admin                                            
[11:28:58] 200 -  854B  - /admin/                                           
[11:28:58] 200 -  854B  - /admin/.config
[11:28:58] 200 -  854B  - /admin/.htaccess
[11:28:58] 200 -  854B  - /admin/?/login
[11:28:58] 200 -  854B  - /admin/_logs/error-log                            
[11:28:58] 200 -  854B  - /admin/admin                                      
[11:28:58] 200 -  854B  - /admin/_logs/access-log                           
[11:28:58] 200 -  854B  - /admin/admin-login                                
[11:28:58] 200 -  854B  - /admin/_logs/access_log                           
[11:28:58] 200 -  854B  - /admin/_logs/error_log                            
[11:28:58] 200 -  854B  - /admin/account                                    
[11:28:58] 200 -  854B  - /admin/%3bindex/                                  
[11:28:58] 200 -  854B  - /admin/access_log
[11:28:58] 200 -  854B  - /admin/admin/login                                
[11:28:59] 200 -  854B  - /admin/backup/                                    
[11:28:59] 200 -  854B  - /admin/admin_login
[11:28:59] 200 -  854B  - /admin/adminLogin
[11:29:00] 200 -  854B  - /admin/dumper/                                    
[11:29:00] 200 -  854B  - /admin/controlpanel                               
[11:29:00] 200 -  854B  - /admin/db/
[11:29:00] 200 -  854B  - /admin/cp
[11:29:00] 200 -  854B  - /admin/backups/
[11:29:00] 200 -  854B  - /admin/default
[11:29:00] 200 -  854B  - /admin/FCKeditor                                  
[11:29:00] 200 -  854B  - /admin/error_log                                  
[11:29:00] 200 -  854B  - /admin/home                                       
[11:29:00] 200 -  854B  - /admin/index                                      
[11:29:00] 200 -  854B  - /admin/index.html                                 
[11:29:00] 200 -  854B  - /admin/js/tiny_mce
[11:29:00] 200 -  854B  - /admin/js/tinymce/
[11:29:00] 200 -  854B  - /admin/log
[11:29:00] 200 -  854B  - /admin/js/tiny_mce/                               
[11:29:00] 200 -  854B  - /admin/js/tinymce
[11:29:00] 200 -  854B  - /admin/login                                      
[11:29:00] 200 -  854B  - /admin/logs/
[11:29:00] 200 -  854B  - /admin/logs/access_log                            
[11:29:00] 200 -  854B  - /admin/manage                                     
[11:29:00] 200 -  854B  - /admin/logs/error_log                             
[11:29:00] 200 -  854B  - /admin/phpMyAdmin
[11:29:00] 200 -  854B  - /admin/phpMyAdmin/                                
[11:29:00] 200 -  854B  - /admin/pma/                                       
[11:29:00] 200 -  854B  - /Admin/login/                                     
[11:29:00] 200 -  854B  - /admin/logs/access-log                            
[11:29:00] 200 -  854B  - /admin/phpmyadmin/                                
[11:29:00] 200 -  854B  - /admin/logs/error-log
[11:29:00] 200 -  854B  - /admin/mysql/
[11:29:00] 200 -  854B  - /admin/pMA/                                       
[11:29:01] 200 -  854B  - /admin/portalcollect.php?f=http://xxx&t=js        
[11:29:01] 200 -  854B  - /admin/scripts/fckeditor
[11:29:01] 200 -  854B  - /admin/tiny_mce
[11:29:01] 200 -  854B  - /admin/private/logs
[11:29:01] 200 -  854B  - /admin/web/                                       
[11:29:01] 200 -  854B  - /admin/sysadmin/                                  
[11:29:02] 200 -  854B  - /admin/signin                                     
[11:29:02] 200 -  854B  - /admin/tinymce
[11:29:02] 200 -  854B  - /admin/sxd/
[11:29:02] 200 -  854B  - /admin/release
[11:29:02] 200 -  854B  - /admin/sqladmin/
[11:29:38] 400 -  182B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[11:30:14] 200 -  413B  - /index.html                                       
[11:31:00] 200 -  507B  - /reviews                                          
[11:31:01] 200 -  121B  - /robots.txt                                       
[11:31:04] 400 -   69B  - /servlet/%C0%AE%C0%AE%C0%AF                       
[11:31:26] 403 -   60B  - /users                                            
[11:31:27] 403 -   60B  - /users/                                           
[11:31:27] 403 -   60B  - /users/login.php                                  
[11:31:27] 403 -   60B  - /users/admin                                      
[11:31:27] 403 -   60B  - /users/login.html
[11:31:27] 403 -   60B  - /users/login.jsp
[11:31:27] 403 -   60B  - /users/login.aspx                                 
[11:31:27] 403 -   60B  - /users/login                                      
[11:31:27] 403 -   60B  - /users/login.js                                   
[11:31:27] 403 -   60B  - /users/admin.php  
```
打开admin后台界面，发现其使用strapi CMS：
![[../attaches/Pasted image 20220120115447.png]]
![[../attaches/Pasted image 20220120115808.png]]
检索漏洞得到：
![[../attaches/Pasted image 20220120121733.png]]
利用漏洞得到admin/SuperStrongPassword1
登录成功，并得到命令执行窗口
