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
- Matches the rules and originates from the score given to each server
You can customize the score for each rule. In other words, the more critical the command, the higher the starting point.
You can define rules to stop the process as soon as a dangerous command is executed.
- You can reduce your score over time. Can put an expiration date on old servers.
- Automatically stops processes started on servers that have lost their scores.
- You can define specific actions for a server that has a zero score.

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

### [Triggers]

### [TimeDecrement]

### [LogDir]

### [noTrusts]


