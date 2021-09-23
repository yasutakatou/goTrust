/*
 * Zero Trust for Legacy Linux by Golang
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   xxx
 */
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/subgraph/inotify"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"

	pb "yasutakatou/goTrust/proto"
)

type serverRuleData struct {
	SCORE   int
	ACT     string
	EXEC    string
	CMDLINE []string
	NOPATH  string
}

type clientRuleData struct {
	EXEC    string
	CMDLINE []string
	NOPATH  string
}

const (
	reqCmd     = "requestClient"
	hitCmd     = "hitProcess"
	endRuleCmd = "endRules"
)

var (
	debug, logging bool
	serverRules    []serverRuleData
	clientRules    []clientRuleData
)

func main() {
	_client := flag.Bool("client", false, "[-client=client mode (true is enable)]")
	_server := flag.String("server", "127.0.0.1:50005", "[-server=connect server (default: 127.0.0.1:50005)]")
	_port := flag.String("port", ":50005", "[-port=server port (default: :50005)]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Config := flag.String("config", "goTrust.ini", "[-config=config file)]")
	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)

	if *_client == true {
		clientStart(*_server)
	} else {
		serverStart(*_port, *_Config, *_autoRW)
	}

	for {
		fmt.Printf(".")
		time.Sleep(time.Second * time.Duration(3))
	}
	os.Exit(0)
}

func sendServerMsg(stream pb.Logging_LogClient, cmd, str string) {
	req := pb.Request{Cmd: cmd, Str: str}
	if err := stream.Send(&req); err != nil {
		log.Fatalf("can not send %v", err)
		os.Exit(1)
	}
}

func clientStart(server string) {
	conn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("can not connect with server %v", err)
		os.Exit(1)
	}

	client := pb.NewLoggingClient(conn)
	stream, err := client.Log(context.Background())
	if err != nil {
		log.Fatalf("openn stream error %v", err)
		os.Exit(1)
	}

	ctx := stream.Context()
	done := make(chan bool)

	sendServerMsg(stream, reqCmd, "")
	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("can not receive %v", err)
			os.Exit(1)
		}

		if resp.Cmd == endRuleCmd {
			break
		} else {
			if stra := searchPath(resp.Cmd); stra != "" {
				strb := strings.Split(resp.Str, "\t")
				clientRules = append(clientRules, clientRuleData{EXEC: stra, CMDLINE: strb, NOPATH: resp.Cmd})
				fmt.Println("- - - -")
				fmt.Println(stra)
				fmt.Println(strb)
				fmt.Println(resp.Cmd)
			}
		}
	}

	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Fatalf("can not receive %v", err)
				os.Exit(1)
			}
			debugLog("recv: " + resp.Cmd + " " + resp.Str)
		}
	}()

	fmt.Println(clientRules)
	if len(clientRules) > 0 {
		setWatch(stream)
	}

	go func() {
		<-ctx.Done()
		if err := ctx.Err(); err != nil {
			log.Println(err)
		}
		close(done)
	}()
	//<-done
}

type server struct{}

func (s server) Log(srv pb.Logging_LogServer) error {
	ctx := srv.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := srv.Recv()
			if err == io.EOF {
				log.Println("exit")
				return nil
			} else if err == nil {
				switch req.Cmd {
				case reqCmd:
					respRules(srv)
				case hitCmd:
				}
				continue
			} else {
				log.Printf("receive error %v", err)
				continue
			}
		}
	}
}

func concatTab(strs []string) string {
	strb := ""
	for x, stra := range strs {
		if x == 0 {
			strb = stra
		} else {
			strb = "\t" + stra
		}
	}
	return strb
}

func respRules(srv pb.Logging_LogServer) {
	for _, rule := range serverRules {
		resp := pb.Response{Cmd: rule.NOPATH, Str: concatTab(rule.CMDLINE)}
		if err := srv.Send(&resp); err != nil {
			log.Printf("send error %v", err)
		}
	}
	resp := pb.Response{Cmd: endRuleCmd, Str: ""}
	if err := srv.Send(&resp); err != nil {
		log.Printf("send error %v", err)
	}
}

func serverStart(port, config string, autoRW bool) {
	if Exists(config) == true {
		loadConfig(config)
	} else {
		fmt.Printf("Fail to read config file: %v\n", config)
		os.Exit(1)
	}

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	if autoRW == true {
		go func() {
			for {
				select {
				case <-watcher.Events:
					loadConfig(config)
				case <-watcher.Errors:
					fmt.Println("ERROR", err)
				}
			}
		}()
	}

	if err := watcher.Add(config); err != nil {
		fmt.Println("ERROR", err)
	}

	// create listiner
	lis, err := net.Listen("tcp", ":50005")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// create grpc server
	s := grpc.NewServer()
	pb.RegisterLoggingServer(s, server{})

	// and start...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func setWatch(stream pb.Logging_LogClient) {
	var err error

	fmt.Println(len(clientRules))
	watman := make([]*inotify.Watcher, len(clientRules))

	for x, rule := range clientRules {
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

		goRouteWatchStart(watman[x], stream)
	}
}

func ruleSearch(eventName string) bool {
	for x, rule := range serverRules {
		if strings.Index(eventName, rule.EXEC) != -1 {
			processes, err := process.Processes()
			if err != nil {
				fmt.Println(err)
			} else {
				for _, p := range processes {
					strs, err := p.Cmdline()
					if err == nil && processSerch(x, strs) == true {
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
	for _, CMD := range serverRules[x].CMDLINE {
		if strings.Index(processName, serverRules[x].NOPATH) != -1 && CMD == "*" {
			return true
		}

		if strings.Index(processName, serverRules[x].NOPATH) != -1 && strings.Index(processName, CMD) != -1 {
			return true
		}
	}
	return false
}

func goRouteWatchStart(watman *inotify.Watcher, stream pb.Logging_LogClient) {
	go func() {
		for {
			select {
			case ev := <-watman.Event:
				log.Println("event:", ev)
				if ev.Mask == 0x1 || ev.Mask == 0x40000001 {
					if ruleSearch(ev.String()) == true {
						sendServerMsg(stream, hitCmd, ev.String())
						// switch serverRules[x].ACT {
						// case "KILL":
						// 	debugLog(strs + ": Killed!")
						// 	p.Kill()
						// default:
						// }
					}
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

	serverRules = nil

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
							serverRules = append(serverRules, serverRuleData{SCORE: val, ACT: strs[1], EXEC: stra, CMDLINE: strr, NOPATH: strs[2]})
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
