/*
 * Zero Trust for Legacy Linux by Golang
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   xxx
 */
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/subgraph/inotify"
	"gopkg.in/ini.v1"
)

type ruleData struct {
	SCORE   int
	ACT     string
	EXEC    string
	CMDLINE []string
	NOPATH  string
}

var (
	debug, logging bool
	rules          []ruleData
)

func main() {
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Config := flag.String("config", "goTrust.ini", "[-config=config file)]")
	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)

	if Exists(*_Config) == true {
		loadConfig(*_Config)
	} else {
		fmt.Printf("Fail to read config file: %v\n", *_Config)
		os.Exit(1)
	}

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	if *_autoRW == true {
		go func() {
			for {
				select {
				case <-watcher.Events:
					loadConfig(*_Config)
				case <-watcher.Errors:
					fmt.Println("ERROR", err)
				}
			}
		}()
	}

	if err := watcher.Add(*_Config); err != nil {
		fmt.Println("ERROR", err)
	}

	if len(rules) > 0 {
		setWatch()
	}

	for {
		fmt.Printf(".")
		time.Sleep(time.Second * time.Duration(3))
	}
	os.Exit(0)
}

func setWatch() {
	var err error

	fmt.Println(len(rules))
	watman := make([]*inotify.Watcher, len(rules))

	for x, rule := range rules {
		fmt.Println(x)
		watman[x], err = inotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		debugLog("watch: " + rule.EXEC)
		err = watman[x].Watch(rule.EXEC)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		goRouteWatchStart(watman[x])
	}
}

func ruleSearch(eventName string) bool {
	for x, rule := range rules {
		if strings.Index(eventName, rule.EXEC) != -1 {
			processes, err := process.Processes()
			if err != nil {
				fmt.Println(err)
			} else {
				for _, p := range processes {
					strs, err := p.Cmdline()
					if err == nil && processSerch(x, strs) == true {
						switch rules[x].ACT {
						case "KILL":
							debugLog(strs + ": Killed!")
							p.Kill()
						default:
						}
						return true
					}
					//log.Println(eventName + " " + strs)
				}
			}
		}
	}
	return false
}

func processSerch(x int, processName string) bool {
	for _, CMD := range rules[x].CMDLINE {
		if strings.Index(processName, rules[x].NOPATH) != -1 && CMD == "*" {
			return true
		}

		if strings.Index(processName, rules[x].NOPATH) != -1 && strings.Index(processName, CMD) != -1 {
			return true
		}
	}
	return false
}

func goRouteWatchStart(watman *inotify.Watcher) {
	go func() {
		for {
			select {
			case ev := <-watman.Event:
				if ev.Mask == 0x1 || ev.Mask == 0x40000001 {
					if ruleSearch(ev.String()) == true {
						log.Println("process found!")
					}
					//log.Println("event:", ev)
				}
			case err := <-watman.Error:
				log.Println("error:", err)
			}
		}
	}()
}

func loadConfig(configFile string) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"Rules"}

	rules = nil

	cfg, err := ini.LoadSources(loadOptions, configFile)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	setStructs("Rules", cfg.Section("Rules").Body(), 0)
}

func searchPath(filename string) string {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, cmd := range paths {
		if Exists(cmd + "/" + filename) {
			debugLog("Command Exists! : " + cmd + "/" + filename)
			return cmd + "/" + filename
		}
	}

	if Exists(filename) {
		debugLog("File Exists! : " + filename)
		return filename
	}

	debugLog("Not Exists! : " + filename)
	return ""
}

func setStructs(configType, datas string, flag int) {
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if strings.Index(v, "\t") != -1 {
			strs := strings.Split(v, "\t")

			switch flag {
			case 0:
				if len(strs) > 3 {
					var strr []string

					for i := 3; i < len(strs); i++ {
						strr = append(strr, strs[i])
					}

					if stra := searchPath(strs[2]); stra != "" {
						if val, err := strconv.Atoi(strs[0]); err == nil {
							rules = append(rules, ruleData{SCORE: val, ACT: strs[1], EXEC: stra, CMDLINE: strr, NOPATH: strs[2]})
							debugLog(v)
						}
					}
				}
			}
		}
	}
}

func debugLog(message string) {
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
	filename := "inco_" + t.Format(layout) + ".log"

	if Exists(filename) == true {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	}

	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	fmt.Fprintln(file, message)
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
