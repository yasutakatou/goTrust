# goTrust
**Zero Trust tool by Golang**

# Solution
　Do you have an *old system* running in your company?　You try to upgrade it, but it keeps running because the application is legacy and no one can refactor it.　Moreover, the support has expired and it is vulnerable.　No matter how new you make the front end,in backend that old system will continue to exist as a security hole.<br>
　You are told by your boss.　*"eliminate the security risk on this server!"*<br>
　You will be distressed.　This legacy systemcan't use latest EDR by not support, and can't pay cost for refactor just now.　I wish they'd just break! No, let's just break it!!!!!!!<br>
<br>
**Stopping!**<br>
<br>
　This tool, which implements a **simple zero-trust model**, will surely help you with your problem!　And all it takes is the placement of **single binary, cost free**!<br>

## v0.2

- Windows Support (Server and Client!!)
  - Windows is now supported. It works in both client and server modes.
- Retry the connection to the server.
  - The client process used to stop when the connection to the server was lost, but now it retries.
- If the connection to the server times out, it will be no trust mode.
  - It will turn itself into no trust mode when it cannot connect to the server.
- Data score management
  - Search the contents of the monitored files and visualize the importance of the data.
- Rules reset
  - Server rules can now be reset without a process restart.
- Control API for additional features (Data score show, Rule reset, Score control)
  - Created an API for the added functionality

# Feature
- Monitors access to **specific files** and **checks for executed command line string** triggered by them<br>

normal access<br>
　cat /tmp/hogefuga.txt<br>
security incident!<br>
　cat /etc/shadow<br>
note) access "/etc/shadow" and cat, more, less... read file<br>

![1](https://user-images.githubusercontent.com/22161385/135618418-d8a041e1-48f5-4c37-a1da-5155c9049493.gif)

- **Matches the rules** and mange **the score** given to each server<br>

You can **customize the score** for each rule. In other words, the more critical the command, the higher the starting point.　You can define rules to **stop the process** as soon as a dangerous command is executed.<br>

- **Automatically stops processes** started on servers that have lost their scores.<br>

![2](https://user-images.githubusercontent.com/22161385/135618448-a5ed093b-aa07-475f-bd1f-77e168e4f7b2.gif)

- You can **reduce your score over time**. Can put an expiration date on old servers.<br>

- You can define **specific execution** for a server that has a zero score.<br>

## v0.2

### Windows Support (Server and Client!!)

Both server and client are supported when running on Windows.


```
.....hit: "data.txt": WRITE
hit: "data.txt": WRITE
recv: killProcess "C:\Program Files (x86)\sakura\sakura.exe" "C:\Users\aaa01\Desktop\goTrust\data.txt"
"C:\Program Files (x86)\sakura\sakura.exe" "C:\Users\aaa01\Desktop\goTrust\data.txt": Killed!
recv: killProcess "C:\Program Files (x86)\sakura\sakura.exe" "C:\Users\aaa01\Desktop\goTrust\data.txt"
```

### Retry the connection to the server.

The client also stopped working when it could not connect to the server, but we added a retry process. Also, when the number of retries exceeds the limit, the client now switches to no trust mode.

```
..........[retry connect!]
2021/11/14 21:10:41 context canceled
open stream error
...[retry connect!]
open stream error
...[retry connect!]
open stream error
...[retry connect!]
open stream error
...[retry connect!]
open stream error
...[retry connect!]
open stream error
...[retry connect!]
open stream error
...[retry connect!]
[retry success!]
--
...[server missing.. no trust mode!]
...[retry connect!]
open stream error
...[server missing.. no trust mode!]
````

### Data score management

We can now scan the monitored files to determine if the data is risky or not.

```
File Exists! : /tmp/data.txt
data source: /tmp/data.txt score: 100,0,20,
send: 172.29.207.179:50006 data: 172.29.207.179 100,0,20, password:goTrust
```

The added score tells you how important the data is.

```
> curl -k -H "Content-type: application/json" -X POST https://172.29.192.1:50006/api -d "{\"name\":\"show\",\"data\":\"172.29.192.1\",\"password\":\"goTrust\"}"
{"status":"Success","message":".*jobdata.* 0,.*memberid.* 0,.*UserID.* 30,"}
````

### Rules reset

Monitoring rules can now be reset without restarting the process.

```
$ curl -k -H "Content-type: application/json" -X POST https://172.29.207.48:50006/api -d '{"name":"reset","data":"172.29.207.48","password":"goTrust"}'
```

All the rules will have to be reread.

```
put call: 172.29.207.48:43492 path: /api
api PUT) Name: reset Data: 172.29.207.48 Password: goTrust
send reset. resetting rules..
```

### Control API for additional features (Data score show, Rule reset, Score control)

Externally usable API for new features. Score manipulation can now be done via the API.

```
curl -k -H "Content-type: application/json" -X POST https://172.29.192.1:50006/api -d "{\"name\":\"scoreCtl\",\"data\":\"+100,172.29.192.1\",\"password\":\"goTrust\"}"
{"status":"Success","message":"calc +100,172.29.192.1"}
```

# Architecture

1. The client connects to the server using **gRPC**　(**Bidirectional streaming RPC**)<br>
note) I selected gRPC. for must frequent and fast communication to can be dreduce communication overhead<br>
Client<br>
　↓　gRPC　communication start<br>
Server<br>

2. Get the rules that will be triggered from the server. It then monitors the target file accesses and sends the command line string of the process to the server when an access comes in.<br>
note) We selected **inotify** to detect file access. It's been around for a long time, and it's leak-proof and reliable.<br>
Client<br>
　↓　Trigger File, and Command line String<br>
Server<br>

3. The server evaluates the rules it receives and subtracts scores from the clients it manages. If necessary, it will issue an order to the client to stop the process.<br>
note) The server doubles as both an enforcer and a trust engine. It should be split for security and load reasons, but it's hard to develop, so we simplified it.　**:)**<br>
Client<br>
　↑　rule detection, and action send<br>
Server<br>

4. If the score is zero, the server will send to the client that it does not trust it. The client will go into a mode where it will stop all processes except the one it remembered **when the agent started**.<br>
note) This mode will **continue until the credit score is higher than 1**.<br>
Client<br>
　↑　no trust command<br>
Server<br>

note) The score will decrease as the os running time increases same too.
note [v0.2~]) You can choose any combination of server and client, Windows or Linux.

# Usecase
1. client) Place the tool on the server you want to monitor, and set it to run when the server starts.
2. server) **Define the rules** you want to place in the monitoring target into the management server.
3. client) Connect to the management server, which will send process string matching the rules via gRPC communication from client.
4. client) Servers that run dangerous commands or run out of time will get a zero score, so please **receive notifications via Slack or other means**. (trustini.ini -> [noTrusts])
5. client) You can't run anymore all proccess, so **quarantine and forensic**.
6. server) If everything is fine, fix the score and return to normal operation.

# installation

If you want to put it under the path, you can use the following.

```
go get github.com/yasutakatou/goTrust
```

If you want to create a binary and copy it yourself, use the following.

```
git clone https://github.com/yasutakatou/goTrust
cd goTrust
go build .
```

[or download binary from release page](https://github.com/yasutakatou/goTrust/releases). save binary file, copy to entryed execute path directory.

# config file

Configs format is **tab split values**. The definition is ignore if you put **sharp(#)** at the beginning.

### auto read support

**config file supported auto read. so, you rewrite config file, tool not necessaly rerun**.

## rules.ini

This config will write **the rules** that apply to the client.

### [Trusts]

Set the **initial score** value for each IP.<br>
<br>
The following example shows how to set a high default score for bastion server(192.168.0.1) that is used by multiple people, and a low score for the other servers because they have few operations.

```
192.168.0.1	10000
.*	1000
```

### [Rules]

This section define the combination of **files and command strings to be alerted**, and the score to be deducted.<br>

```
4000	NO	ls	passwd	shadow	resolv.conf
1000	KILL	ssh	*
```

1. Score to be **deducted**.
2. "KILL" to stop the target process as soon as it is discovered, "NO" to keep run it.
3. Files to monitor. (**When can execute file, Auto-detect without writing the full path**)
4. String to be checked in **combination with the monitoring file**.

The server side should be started as follows (No specific options.)

```
./goTrust
```

On the client side, specify option "-client" and the server to connect to

```
./goTrust -client -server=127.0.0.1:50005
```

note) **4. can be written to multiple tabs**.<br>

### [Triggers]

Define the access that will trigger the alert. By default, we'll use **file and directory access**. If you want to change the rules to creation or deletion, you can check the following page.

Linux [The hexadecimal version of the trigger list is here](https://github.com/torvalds/linux/blob/master/include/linux/fsnotify_backend.h).
Windows [fsnotify](https://github.com/fsnotify/fsnotify/blob/master/windows.go)

```
#define FS_ACCESS		0x00000001	/* File was accessed */
```

#### v0.2

note) If it starts with "0x", it is interpreted as a **hexadecimal number**.<br>

### [TimeDecrement]

This value is **decrease score of time**.<br>
In the example below, it decreases by 1 every 10 seconds.<br>


```
10	1
```

note) This parameter is also used for **the monitoring interval**. Thus, a small value will cause more grained monitoring, increased processing, and increased logging.

### [LogDir]

This define is **directory name** where the alert logs.<br>
<br>
note)  for each server are saved by **each ip**.

### [noTrusts]

This is the **command operation** to take when a score of **zero occurs**.　The **{}** defined in the argument will be replaced with the **IP address** of the server and executed.

```
.*	echo {} >> noTrustLists
```

In this example, we will output the **IP of the server where the zero score occurred** to the specified file name.<br>
<br>
note) Based on the added IP, the idea of shutting down the server from the cloud API can be used to enhance security.

### [AllowIP]

Define the IP address to allow connection<br>

```
127.0.0.1
```

### [dataScore]

Defines the importance of the data file. With this definition, scan files with regular expressions and tally the importance of the files.

```
10	.*UserID.*
```

## trust.ini

It's a file for manage **server and the score**.<br>
<br>
note) **If you want to trust a server with a zero score again, please rewrite the score field in this file directly. **.

```
[Scores]
172.22.28.236	998	DESKTOP-V58043T 5.10.16.3-microsoft-standard-WSL2Linux #1 SMP Fri Apr 2 22:23:49 UTC 2021 x86_64 localdomaininn
```

The string after the score value is the result of **system uname**.

# API (v0.2)

We have created APIs for manipulating scores, resetting rules, and manipulating scores in the data file, and the APIs are called by REST.

- name: API Name
- data: API Parameter (Specify the IP to operate, etc.)
- password: API Password (The password to specify for the API. It is specified in the startup options.)

```
curl -k -H "Content-type: application/json" -X POST https://172.29.207.179:50006/api -d '{"name":"show","data":"172.29.207.179","password":"goTrust"}'
```

## show

Make sure that high-risk data is stored for each monitoring target.

```
>curl -k -H "Content-type: application/json" -X POST https://172.29.192.1:50006/api -d "{\"name\":\"show\",\"data\":\"172.29.192.1\",\"password\":\"goTrust\"}"
{"status":"Success","message":".*jobdata.* 0,.*memberid.* 0,.*UserID.* 30,"}
```

## reset

Redo the monitoring configuration.

```
curl -k -H "Content-type: application/json" -X POST https://172.29.207.48:50006/api -d '{"name":"reset","data":"172.29.207.48","password":"goTrust"}'
```

## scoreCtl

Manipulate scores via API. You can decide whether to add or subtract the score by specifying + or - before the number.

```
>curl -k -H "Content-type: application/json" -X POST https://172.29.192.1:50006/api -d "{\"name\":\"scoreCtl\",\"data\":\"+100,172.29.192.1\",\"password\":\"goTrust\"}"
{"status":"Success","message":"calc +100,172.29.192.1"}
```

```
 -- Scores --
172.29.207.48   592     DESKTOP-V58043T172.29.207.488
put call: 172.29.207.48:43634 path: /api
api PUT) Name: scoreCtl Data: +100,172.29.207.48 Password: goTrust
 - - - - - 
[O] IP: 172.29.207.48 Score: 691 Detail: DESKTOP-V58043T172.29.207.488
````

# options

```
Usage of ./goTrust:
  ★-ApiPassword string
        [-secret=api password] (default "goTrust")
  -allowOverride
        [-allowOverride=trust file override mode (true is enable)]
  ★-api string
        [-api=api port (default: :50006)] (default ":50006")
  -auto
        [-auto=config auto read/write mode (true is enable)] (default true)
  -client
        [-client=client mode (true is enable)]
  ★-clientDisconnect int
        [-clientDisconnect=client live interval ] (default 60)
  ★-dataScanCount int
        [-dataScanCount=data score count lines.] (default 1000)
  -debug
        [-debug=debug mode (true is enable)]
  ★-filterCount int
        [-filterCount=allow connect retrys.] (default 3)
  ★-grpc string
        [-grpc=grpc port (default: :50005)] (default ":50005")
  ★-key string
        [-key=ssl_certificate_key file path] (default "localhost-key.pem")        
  -lock string
        [-lock=lock file name and path] (default "lock")
  -log
        [-log=logging mode (true is enable)]
  -port string
        [-port=server port (default: :50005)] (default ":50005")
  -replaceString string
        [-replaceString= when no trust action, give ip paramater] (default "{}")
  -rule string
        [-rule=rules config file] (default "rules.ini")
  -server string
        [-server=connect server (default: 127.0.0.1:50005)] (default "127.0.0.1:50005")
  -server string
        [-server=connect server (default: 127.0.0.1:50005)] (default "127.0.0.1:50005")
  -trust string
        [-trust=trusts config file)] (default "trust.ini")
```

note) The options marked with ★ can be specified from v0.2.

## -allowOverride

This option is **allow overwrite** the information of just connecting client if it already exists in trust.ini.<br>
<br>
note) This is useful if you want to use it to restart the agent in regularly.

## -ApiPassword

The password to be specified when calling the API.

note) We will consider encrypting it in the future.

## -api

Port number to use for the API.

## -auto

config auto read/write mode.<br>
<br>
note) Its enable in both **trust.ini** and **rule.ini**

## -client

start client mode.<br>
<br>
note) Without this option, it will start in **server mode**.

## -cert

ssl_certificate file path (if you don't use https, haven't to use this option)

## -clientDisconnect

The length of time the client will be allowed to reconnect.

note) If the connection to the server times out, it will be no trust mode.

## -dataScanCount

Number of rows to read when scoring in a data file. The larger the number, the more multiple rows of data will be read.

## -debug

Run in the mode that outputs various logs.

## -filterCount

Number of retries to allow reconnection in case of wrong password.

## -lock string

Specify the lock file name.<br>
<br>
note) Used to perform lock processing when updating **trust.ini**

## -log

Specify the log file name.

## -grpc string

gRPC port number<br>
<br>
note) Used when in **server mode**.

## -key

ssl_certificate_key file path (if you don't use https, haven't to use this option)

## -replaceString string

Define the string to be replaced by the execution result at actions.<br>
<br>
note) It's the **{}** in **[noTrusts]**.

```
.*	echo {} >> noTrustLists
```

## -rule string

Specify the rules(**rule.ini**) file name.

## -server string

Define the string to be replaced when **no trust** action.<br>
<br>
note) It's the **{}** in **[noTrusts]**.

```
-server=127.0.0.1:50005
```

## -trust string

Specify the score(**trust.ini**) file name.

# license

3-clause BSD License
and
Apache License Version 2.0
