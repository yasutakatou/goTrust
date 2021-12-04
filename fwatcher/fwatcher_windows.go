package fwatcher

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	pb "yasutakatou/goTrust/proto"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/process"
)

var (
	resetFlag = false
)

const (
	hitCmd  = "hitProcess"
	pingCmd = "hello"
)

type ClientRuleData struct {
	EXEC    string
	CMDLINE []string
	NOPATH  string
}

func SetWatch(stream pb.Logging_LogClient, clientRules []ClientRuleData, myIp string, cliTriggers []uint32, logging, debug bool) {
	var err error

	watman := make([]*fsnotify.Watcher, len(clientRules))

	for x, rule := range clientRules {
		watman[x], err = fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		DebugLog("watch: "+rule.EXEC, logging, debug)
		err = watman[x].Add(rule.EXEC)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		GoRouteWatchStart(watman[x], stream, clientRules, myIp, cliTriggers, logging, debug)
	}
}

func GoRouteWatchStart(watman *fsnotify.Watcher, stream pb.Logging_LogClient, clientRules []ClientRuleData, myIp string, cliTriggers []uint32, logging, debug bool) {
	go func() {
		for {
			if resetFlag == true {
				resetFlag = false
				return
			}
			select {
			case ev := <-watman.Events:
				if TriggerChecker(uint32(ev.Op), cliTriggers) {
					DebugLog("hit: "+ev.String(), logging, debug)
					if strs := RuleSearch(ev.String(), clientRules); len(strs) > 0 {
						SendClientMsg(stream, hitCmd, myIp+"\t"+strs)
					}
				}
			case err := <-watman.Errors:
				log.Println("error:", err)
			}
		}
	}()

	go func() {
		for {
			if resetFlag == true {
				resetFlag = false
				return
			}
			SendClientMsg(stream, pingCmd, myIp)
			time.Sleep(time.Second * time.Duration(1))
		}
	}()

}

func TriggerChecker(ev uint32, cliTriggers []uint32) bool {
	for _, x := range cliTriggers {
		if ev == x {
			return true
		}
	}
	return false
}

func RuleSearch(eventName string, clientRules []ClientRuleData) string {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(eventName + " " + strs)
			if err == nil && ProcessSerch(strs, clientRules) == true {
				return strs
			}
		}
	}

	return ""
}

func ProcessSerch(processName string, clientRules []ClientRuleData) bool {
	for i := 0; i < len(clientRules); i++ {
		for _, CMD := range clientRules[i].CMDLINE {
			if strings.Index(processName, clientRules[i].NOPATH) != -1 && CMD == "*" {
				return true
			}

			if strings.Index(processName, clientRules[i].NOPATH) != -1 && strings.Index(processName, CMD) != -1 {
				return true
			}
		}
	}
	return false
}

func DebugLog(message string, logging, debug bool) {
	var file *os.File
	var err error

	if debug == true {
		fmt.Println(message)
	}

	if logging == false {
		return
	}

	const layout = "2006-01-02_15"
	t := time.Now()
	filename := "goTrust_" + t.Format(layout) + ".log"

	if Exists(filename) == true {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	}

	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	fmt.Fprintln(file, message)
}

func SendClientMsg(stream pb.Logging_LogClient, cmd, str string) {
	//debugLog("sendClientMsg Command: " + cmd + " String: " + str)
	req := pb.Request{Cmd: cmd, Str: str}
	if err := stream.Send(&req); err != nil {
		fmt.Printf("watcher: client missing! can not send %v\n", err)
		//os.Exit(1)
	}
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func ResetCheck() bool {
	return resetFlag
}

func ResetTrue() {
	resetFlag = true
}

func ResetFalse() {
	resetFlag = false
}
