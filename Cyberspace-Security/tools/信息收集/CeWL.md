## CeWL
#信息收集 #字典生成
kali
```
./cewl.rb

CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
Usage: cewl [OPTIONS] ... <url>

    OPTIONS:
	-h, --help: Show help.
	-k, --keep: Keep the downloaded file.
	-d <x>,--depth <x>: Depth to spider to, default 2.
	-m, --min_word_length: Minimum word length, default 3.
	-o, --offsite: Let the spider visit other sites.
	-w, --write: Write the output to the file.
	-u, --ua <agent>: User agent to send.
	-n, --no-words: Don't output the wordlist.
	-a, --meta: include meta data.
	--meta_file file: Output file for meta data.
	-e, --email: Include email addresses.
	--email_file <file>: Output file for email addresses.
	--meta-temp-dir <dir>: The temporary directory used by exiftool when parsing files, default /tmp.
	-c, --count: Show the count for each word found.
	-v, --verbose: Verbose.
	--debug: Extra debug information.

	Authentication
	--auth_type: Digest or basic.
	--auth_user: Authentication username.
	--auth_pass: Authentication password.

	Proxy Support
	--proxy_host: Proxy host.
	--proxy_port: Proxy port, default 8080.
	--proxy_username: Username for proxy, if required.
	--proxy_password: Password for proxy, if required.

	Headers
	--header, -H: In format name:value - can pass multiple.

    <url>: The site to spider.
```