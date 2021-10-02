# goTrust (document writing..)
*Zero Trust for Legacy Linux by Golang*

# Solution
Do you have an old Linux system running in your company?
You try to upgrade it, but it keeps running because the application is legacy and no one can refactor it.
Moreover, the support has expired and it is vulnerable.
No matter how new you make the front end, that old system will continue to exist as a security hole.
You are told by your boss.
"I want to eliminate the security risk on this server."
You will be distressed.
This tool, which implements a simple zero-trust model, will surely help you with your problem!
And all it takes is the placement of a single binary to make this happen for free!

# Feature
- Monitors access to specific files and checks for executed commands triggered by them
normal access
	cat /tmp/hogefuga.txt
security incident!
	cat /etc/shadow
tool trapped access "/etc/shadow" and cat, more, less... read command check

![1](https://user-images.githubusercontent.com/22161385/135618418-d8a041e1-48f5-4c37-a1da-5155c9049493.gif)

- Matches the rules and originates from the score given to each server
You can customize the score for each rule. In other words, the more critical the command, the higher the starting point.
You can define rules to stop the process as soon as a dangerous command is executed.
- Automatically stops processes started on servers that have lost their scores.

![2](https://user-images.githubusercontent.com/22161385/135618448-a5ed093b-aa07-475f-bd1f-77e168e4f7b2.gif)

- You can reduce your score over time. Can put an expiration date on old servers.
- You can define specific actions for a server that has a zero score.

# Architecture

1. The client connects to the server using gRPC　(Bidirectional streaming RPC)
note) gRPC is selected for frequent and fast communication to reduce communication overhead
Client
  ↓ gRPC
Server

2. Get the rules that will be triggered from the server. It then monitors the target file accesses and sends the command line string of the process to the server when an access comes in.
note) We selected inotify to detect file access. It's been around for a long time, and it's leak-proof and reliable.
Client
  ↓ Trigger File, and Command line String
Server

3. The server evaluates the rules it receives and subtracts scores from the clients it manages. If necessary, it will issue an order to the client to stop the process.
note) The server doubles as both an enforcer and a trust engine. It should be split for security and load reasons, but it's hard to develop, so we simplified it.　:)
Client
  ↑ gRPC
Server

4. If the score is zero, the server will send to the client that it does not trust it. The client will go into a mode where it will stop all processes except the one it remembered when the agent started.
note) This mode will continue until the credit score is higher than zero. The score will also decrease as the operation time increases.
Client
  ↑ gRPC
Server


# Usecase
1. Place the tool on the server you want to monitor, and set it to run when the server starts.
2. Define the rules you want to place in the monitoring target on the management server.
3. Run it against the monitoring server, which will send logs matching the rules via gRPC communication.
4. Servers that run dangerous commands or run out of time will get a zero score, so please receive notifications via Slack or other means.
5. You can't move anything anymore, so quarantine and forensic. If everything is fine, fix the score and return to normal operation.

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

[or download binary from release page](https://github.com/yasutakatou/IMS/releases). save binary file, copy to entryed execute path directory.

# config file

Configs format is tab split values. The definition is ignore if you put sharp(#) at the beginning.

auto read suppot
config file supported auto read. so, you rewrite config file, tool not necessaly rerun, tool just this.

## rules.ini

This config will write the rules that apply to the server.

### [Trusts]
Set the initial score value for each IP.

The following example shows how to set a high score for a stepping stone server that is used by multiple people, and a low score for the other servers because they have few logins.

```
192.168.0.1	10000
.*	1000
```

### [Rules]

This section describes the combination of files and command strings to be alerted, and the score to be deducted.

```
4000	NO	ls	passwd	shadow	resolv.conf
1000	KILL	ssh	*
```

1. Score to be deducted
2. KILL" to drop the process as soon as it is discovered, "NO" to keep it.
3. Files to monitor
4. String to be alerted in combination with the monitoring file

note. 4. can be written in multiple tabs.

### [Triggers]

Define the access that will trigger the file. For now, we'll use file and directory access. If you want to relax the rules for creation and deletion, you can do so in the

[The hexadecimal version of the trigger list is here](https://github.com/torvalds/linux/blob/master/include/linux/fsnotify_backend.h).

```
#define FS_ACCESS		0x00000001	/* File was accessed */
```

### [TimeDecrement]

It is the sense of time and the score that is subtracted.
In the example below, it decreases by 1 every 10 seconds.

```
10	1
```

This parameter is also used for the monitoring interval. Thus, a small value will cause fine-grained monitoring, increased processing, and increased logging.

### [LogDir]

The directory where the alert logs for each server are saved.

### [noTrusts]

This is the action to take when a score of zero occurs.
The {} defined in the argument will be replaced with the IP address of the server and executed.

```
.*	echo {} >> noTrustLists
```

In this example, we will add the IP of the server where the zero score occurred to the specified file name.

note. Based on the added IP, the idea of shutting down the server from the cloud API can be used to enhance security.

## rules.ini

It's a file with the server and the score.

note. If you want to trust a server with a zero score again, please rewrite the score field in this file directly. Hot reload and monitoring will resume.

```
[Scores]
172.22.28.236	998	DESKTOP-V58043T 5.10.16.3-microsoft-standard-WSL2Linux #1 SMP Fri Apr 2 22:23:49 UTC 2021 x86_64 localdomaininn
```

The string after the score is the result of uname.

# options

```ady@DESKTOP-V58043T:~/goTrust$ ./goTrust -h
Usage of ./goTrust:
  -allowOverride
        [-allowOverride=trust file override mode (true is enable)]
  -auto
        [-auto=config auto read/write mode (true is enable)] (default true)
  -client
        [-client=client mode (true is enable)]
  -debug
        [-debug=debug mode (true is enable)]
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
  -trust string
        [-trust=trusts config file)] (default "trust.ini")
```

## -allowOverride

Overwrite the information of a newly connected client if it already exists.

## -auto

config auto read/write mode.

## -client

start client mode.

## -debug

Run in the mode that outputs various logs.

## -lock string

Specify the lock file name.

## -log

Specify the log file name.

## -port string

port number

## -replaceString string

Define the string to be replaced by the execution result at actions.

## -rule string

Specify the rules file name.

## -server string

Defines the server to connect to when in client mode.

## -trust string

Specify the score file name.

# license

3-clause BSD License
and
Apache License Version 2.0
