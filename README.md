# secured-api-call
the project aims to practice library injection,API hijacking and GOT rewriting. using sandbos.so to hijack API function to monitor the process.
## How to use
```shell=
make
./launcher sandbox.so config.txt [command] [arg1] [arg2] ...
```

## Specfication
### Program Launcher
We use a launcher program to execute a command and load your `sandbox.so` using `LD_PRELOAD`.The launcher executes the command and passes the required environment variables to an invoked process. The environment variables include:
- `SANDBOX_CONFIG`: The path of the configuration file for `sandbox.so`.
- `LOGGER_FD`: the file descriptor (fd) for logging messages.
The usage of the `launcher` program is as follows
```shell=
Usage: ./launcher sandbox.so config.txt command arg1 arg2 ...
```
### Sandbox
implement `sandbox.so` that support the following features:
- implement a `__libc_start_main` to hijack the process's entry point
- in `__libc_start_main`, i perform the necessary initalizations and then call then call the real `__libc_start_main`
- in `sandbox.so` , i perform GOT hijacking to hijack all API functions 

### API function list
All functions listed below should be logged to the file descriptor (fd) passed by the environment variable `LOGGER_FD`
1. `open`
Allow a user to set the file access blacklist so that files listed in the blacklist cannot be opened. If a file is in the blacklist, return -1 and set `errno` to EACCES. Note that for handling symbolic linked files, your implementation has to follow the links before performing the checks.

2. `read`
I log the context of read in `{pid}-{fd}.log`
Furthermore, I allow a user to filter the read content based on a keyword blacklist. The filter should be active for all read operations. If the filter detects a matched keyword in a read content, close the fd and return -1 with an `errno` setting to `EIO`. Do not log the content if it is filtered.
Suppose the blacklist contains the keyword S3CR3T. The following cases should be detected by the filter. 
Reading gets `abcd`, `def`, `S3CR3T` 
Reading gets `abcd`, `S3C`, `R3T` (should be detected on read of the `R3T`)

3. `wirte`
I log the context of write in `{pid}-{fd}.log`

4. `connect`
Allow a user to block connection setup to specific IP addresses and PORT numbers. If the IP and PORT is blocked, return -1 and set `errno` to ECONNREFUSED.

5. `getaddrinfo`
Allow a user to block specific host name resolution requests. If a host is blocked, return EAI_NONAME.

6. `system`
Commands invoked by system function is hijacked and monitored by sandbox.so.

### Configuration File Format
The configuration file is a text file containing blocked content for each API function. For each API, the general form is as follows.
```txt=
BEGIN <API>-blacklist
rule1
rule2
...
END <API>-blacklist
```

### Examples
#### Exmaple 1
- command : `./launcher ./sandbox.so config.txt cat /etc/passwd`
- output:
```shell=
[logger] open("/etc/passwd", 0, 0) = -1
cat: /etc/passwd: Permission denied
```
#### Exmaple 2
- command : `./launcher ./sandbox.so config.txt cat /etc/hosts`
- output:
```shell=
[logger] open("/etc/hosts", 0, 0) = 5
[logger] read(5, 0x7fb7b2db2000, 131072) = 177
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.168.208.2   00fd90b988c7
[logger] write(1, 0x7fb7b2db2000, 177) = 177
[logger] read(5, 0x7fb7b2db2000, 131072) = 0
```

#### Exmaple 3
- command : `./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem`
- output:
```shell=
[logger] open("/usr/share/ca-certificates/mozilla/Amazon_Root_CA_1.crt", 0, 0) = 5
[logger] read(5, 0x7f6a9c486000, 131072) = -1
cat: /etc/ssl/certs/Amazon_Root_CA_1.pem: Input/output error
cat: /etc/ssl/certs/Amazon_Root_CA_1.pem: Bad file descriptor
```


#### Exmaple 4
- command : `./launcher ./sandbox.so config.txt wget http://google.com -t 1`
- output:
```shell=
--2023-03-29 15:07:09--  http://google.com/
Resolving google.com (google.com)... [logger] getaddrinfo("google.com","(null)",0x7ffcbde22320,0x7ffcbde222e8) = -2
failed: Name or service not known.
wget: unable to resolve host address 'google.com'
```



#### Exmaple 5
- command : `./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'`
- output:
```shell=
[logger] read(5, 0x560ce341c5e0, 3908) = 3907
[logger] read(5, 0x560ce341d523, 1) = 0
[logger] read(5, 0x560ce341cad0, 33180) = 33179
[logger] read(5, 0x560ce3424c6b, 1) = 0
[logger] read(5, 0x560ce3428530, 10922) = 10921
[logger] read(5, 0x560ce342afd9, 1) = 0
[logger] read(5, 0x560ce3429540, 1598) = 1597
[logger] read(5, 0x560ce3429b7d, 1) = 0
[logger] read(5, 0x560ce342b990, 3664) = 3663
[logger] read(5, 0x560ce342c7df, 1) = 0
[logger] read(5, 0x560ce342fd60, 6752) = 6751
[logger] read(5, 0x560ce34317bf, 1) = 0
[logger] read(5, 0x560ce3433b00, 17923) = 17922
[logger] read(5, 0x560ce3438102, 1) = 0
[logger] read(5, 0x560ce3434b10, 31557) = 31556
[logger] read(5, 0x560ce343c654, 1) = 0
[logger] read(5, 0x560ce3435af0, 4274) = 4273
[logger] read(5, 0x560ce3436ba1, 1) = 0
[logger] read(5, 0x560ce3404330, 32838) = 32837
[logger] read(5, 0x560ce340c375, 1) = 0
[logger] read(5, 0x560ce340c3f0, 10516) = 10515
[logger] read(5, 0x560ce340ed03, 1) = 0
[logger] read(5, 0x560ce3408d20, 3908) = 3907
[logger] read(5, 0x560ce3409c63, 1) = 0
[logger] read(5, 0x560ce340bf40, 3548) = 3547
[logger] read(5, 0x560ce340cd1b, 1) = 0
[logger] read(5, 0x7f7bafc41150, 226) = 225
[logger] read(5, 0x7f7bafc41231, 1) = 0
[logger] system("wget http://www.google.com -q -t 1")
[logger] getaddrinfo("www.google.com","(null)",0x7ffd704a8120,0x7ffd704a80e8) = 0
[logger] connect(9, "142.251.43.4", 16) = 0
[logger] write(9, 0x55f9bb917110, 129) = 129
[logger] read(9, 0x55f9bb9171a0, 511) = 511
[logger] read(9, 0x55f9bb91739f, 512) = 512
[logger] read(9, 0x55f9bb91759f, 129) = 129
[logger] read(9, 0x55f9bb917110, 6) = 6
[logger] read(9, 0x55f9bb925990, 8192) = 8192
[logger] read(9, 0x55f9bb925990, 6383) = 4650
[logger] read(9, 0x55f9bb925990, 1733) = 1733
[logger] read(9, 0x55f9bb917110, 2) = 2
[logger] read(9, 0x55f9bb917110, 3) = 3
[logger] read(9, 0x55f9bb917110, 2) = 2
```
