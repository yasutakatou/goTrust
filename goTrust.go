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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/process"
	"github.com/subgraph/inotify"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"

	pb "yasutakatou/goTrust/proto"
)

type trustData struct {
	FILTER string
	SCORE  int
}

type clientsData struct {
	IP     string
	DETAIL string
	SCORE  int
}

type serverRuleData struct {
	SCORE   int
	ACT     string
	EXEC    string
	CMDLINE []string
}

type clientRuleData struct {
	EXEC    string
	CMDLINE []string
	NOPATH  string
}

const (
	reqCmd        = "requestClient"
	hitCmd        = "hitProcess"
	endRuleCmd    = "endRules"
	killCmd       = "killProcess"
	noTrustCmd    = "noTrust"
	reTrustCmd    = "reTrust"
	exitCmd       = "exitClient"
	addTriggerCmd = "addTrigger"
)

var (
	debug, logging, noTrust, allowOverride bool
	trustFile, lockFile, LogDir            string
	trusts                                 []trustData
	clients                                []clientsData
	serverRules                            []serverRuleData
	clientRules                            []clientRuleData
	svrTriggers                            []string
	cliTriggers                            []uint32
	TimeDecrement                          [2]int
	myIp                                   string
)

func main() {
	_client := flag.Bool("client", false, "[-client=client mode (true is enable)]")
	_server := flag.String("server", "127.0.0.1:50005", "[-server=connect server (default: 127.0.0.1:50005)]")
	_port := flag.String("port", ":50005", "[-port=server port (default: :50005)]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Rule := flag.String("rule", "rules.ini", "[-rule=rules config file)]")
	_Trust := flag.String("trust", "trust.ini", "[-trust=trusts config file)]")
	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")
	_Lock := flag.String("lock", "lock", "[-lock=lock file name and path]")
	_allowOverride := flag.Bool("allowOverride", false, "[-allowOverride=trust file override mode (true is enable)]")

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)
	lockFile = string(*_Lock)
	trustFile = string(*_Trust)
	allowOverride = bool(*_allowOverride)

	if *_client == true {
		clientStart(*_server)
	} else {
		serverStart(*_port, *_Rule, *_autoRW)
	}

	for {
		fmt.Printf(".")
		time.Sleep(time.Second * time.Duration(3))
	}
	os.Exit(0)
}

func sendClientMsg(stream pb.Logging_LogClient, cmd, str string) {
	req := pb.Request{Cmd: cmd, Str: str}
	if err := stream.Send(&req); err != nil {
		log.Fatalf("can not send %v", err)
		os.Exit(1)
	}
}

func sendServerMsg(stream pb.Logging_LogServer, cmd, str string) {
	req := pb.Response{Cmd: cmd, Str: str}
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

	_, ip, err := getIFandIP()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	myIp = ip

	sendClientMsg(stream, reqCmd, myIp+"\t"+uname())
	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("can not receive %v", err)
			os.Exit(1)
		}

		if resp.Cmd == endRuleCmd {
			break
		}

		switch resp.Cmd {
		case exitCmd:
			stream.CloseSend()
			debugLog("add client failed..")
			os.Exit(1)
		case addTriggerCmd:
			if val, err := strconv.ParseUint(resp.Str, 10, 32); err == nil {
				cliTriggers = append(cliTriggers, uint32(val))
			} else {
				log.Fatal(err)
			}
		default:
			if stra := searchPath(resp.Cmd); stra != "" {
				strb := strings.Split(resp.Str, "\t")
				clientRules = append(clientRules, clientRuleData{EXEC: stra, CMDLINE: strb, NOPATH: resp.Cmd})
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
			switch resp.Cmd {
			case killCmd:
				killProcessName(resp.Str)
			case exitCmd:
				stream.CloseSend()
				debugLog("add client failed..")
				os.Exit(1)
			}
		}
	}()

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
					if addClient(req.Str) == true {
						respRules(srv)
					} else {
						debugLog("no match client rule: " + req.Str)
						sendServerMsg(srv, exitCmd, "")
					}
				case hitCmd:
					if actRules(srv, req.Str) == true {
						sendServerMsg(srv, killCmd, strings.Split(req.Str, "\t")[1])
					}
				}
				continue
			} else {
				log.Printf("receive error %v", err)
				continue
			}
		}
	}
}

func uname() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		fmt.Printf("Uname: %v", err)
	}
	return arrayToString(uname.Nodename) + " " + arrayToString(uname.Release) + arrayToString(uname.Sysname) + " " + arrayToString(uname.Version) + " " + arrayToString(uname.Machine) + " " + arrayToString(uname.Domainname)
}

func arrayToString(x [65]int8) string {
	var buf [65]byte
	for i, b := range x {
		buf[i] = byte(b)
	}
	str := string(buf[:])
	if i := strings.Index(str, "\x00"); i != -1 {
		str = str[:i]
	}
	return str
}

func addClient(ip string) bool {
	ride := 0
	ips := strings.Split(ip, "\t")
	for x, client := range clients {
		if client.IP == ips[0] {
			if allowOverride == false {
				debugLog("clients exsits: " + ips[0])
				return false
			} else {
				ride = x + 1
				break
			}
		}
	}
	for _, rule := range trusts {
		ipRegex := regexp.MustCompile(rule.FILTER)
		if ipRegex.MatchString(ips[0]) == true {
			if ride > 0 {
				clients[ride-1].SCORE = rule.SCORE
				debugLog("override client: " + ips[0] + " " + uname())
			} else {
				clients = append(clients, clientsData{IP: ips[0], SCORE: rule.SCORE, DETAIL: ips[1]})
				debugLog("add client: " + ips[0] + " " + uname())
			}
			return true
		}
	}
	return false
}

func exportClients() {
	if Exists(lockFile) == false {
		lfile, err := os.Create(lockFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		lfile.Close()

		file, err := os.OpenFile(trustFile, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		_, err = file.WriteString("[Scores]\n")
		for i := 0; i < len(clients); i++ {
			convInt := strconv.Itoa(clients[i].SCORE)
			_, err = file.WriteString(clients[i].IP + "\t" + convInt + "\t" + clients[i].DETAIL + "\n")
		}

		time.Sleep(time.Second * time.Duration(1))

		if err := os.Remove(lockFile); err != nil {
			fmt.Println(err)
		}
		return
	}
}

func actRules(srv pb.Logging_LogServer, act string) bool {
	acts := strings.Split(act, "\t")
	for i := 0; i < len(serverRules); i++ {
		for _, CMD := range serverRules[i].CMDLINE {
			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && CMD == "*" {
				exportLog(acts[0], serverRules[i], decrementScore(acts[0], serverRules[i].SCORE))
				return true
			}

			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && strings.Index(acts[1], CMD) != -1 {
				exportLog(acts[0], serverRules[i], decrementScore(acts[0], serverRules[i].SCORE))
				return true
			}
		}
	}
	return false
}

func exportLog(ip string, rule serverRuleData, score int) {
	var file *os.File
	var err error

	const layouta = "2006-01-02_15"
	t := time.Now()
	const layoutb = "2006-01-02_15-04-05"
	tt := time.Now()

	filename := LogDir + "/" + ip + "_" + t.Format(layouta) + ".log"

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
	fmt.Fprintln(file, tt.Format(layoutb)+" | IP: "+ip+" Score: "+strconv.Itoa(score)+" | Score: "+strconv.Itoa(rule.SCORE)+" EXEC: "+rule.EXEC+" ACT: "+rule.ACT)
}

func decrementScore(ip string, score int) int {
	for i := 0; i < len(clients); i++ {
		if clients[i].SCORE-score > 0 {
			clients[i].SCORE = clients[i].SCORE - score
			return clients[i].SCORE
		} else {
			clients[i].SCORE = 0
			return 0
		}
	}
	return 0
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
	for _, rule := range svrTriggers {
		sendServerMsg(srv, addTriggerCmd, rule)
	}

	for _, rule := range serverRules {
		sendServerMsg(srv, rule.EXEC, concatTab(rule.CMDLINE))
	}
	sendServerMsg(srv, endRuleCmd, "")
}

func serverStart(port, config string, autoRW bool) {
	if Exists(config) == true {
		loadConfig(config, true)
	} else {
		fmt.Printf("Fail to read config file: %v\n", config)
		os.Exit(1)
	}

	if Exists(trustFile) == true {
		loadConfig(trustFile, false)
	} else {
		fmt.Printf("Fail to read trust file: %v\n", config)
		os.Exit(1)
	}

	if autoRW == true {
		// creates a new file watcher
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
		defer watcher.Close()

		go func() {
			for {
				select {
				case <-watcher.Events:
					loadConfig(config, true)
				case <-watcher.Errors:
					fmt.Println("ERROR", err)
					os.Exit(1)
				}
			}
		}()

		if err := watcher.Add(config); err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}

		// creates a new file watcher
		trust, err := fsnotify.NewWatcher()
		if err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
		defer trust.Close()

		go func() {
			for {
				select {
				case <-trust.Events:
					if Exists(lockFile) == false {
						loadConfig(trustFile, false)
					}
				case <-trust.Errors:
					fmt.Println("ERROR", err)
					os.Exit(1)
				}
			}
		}()

		if err := trust.Add(trustFile); err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
	}

	// create listiner
	lis, err := net.Listen("tcp", ":50005")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// create grpc server
	s := grpc.NewServer()
	pb.RegisterLoggingServer(s, server{})

	go func() {
		for {
			time.Sleep(time.Second * time.Duration(TimeDecrement[0]))
			fmt.Println(" - - - - - ")
			for i := 0; i < len(clients); i++ {
				if clients[i].SCORE-TimeDecrement[1] > 0 {
					clients[i].SCORE = clients[i].SCORE - TimeDecrement[1]
				} else {
					clients[i].SCORE = 0
				}
				fmt.Printf("IP: %s Score: %d Detail: %s\n", clients[i].IP, clients[i].SCORE, clients[i].DETAIL)
			}
			exportClients()
		}
	}()

	// and start...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func setWatch(stream pb.Logging_LogClient) {
	var err error

	watman := make([]*inotify.Watcher, len(clientRules))

	for x, rule := range clientRules {
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

func killProcessName(processName string) {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(eventName + " " + strs)
			if err == nil && processSerch(strs) == true {
				debugLog(strs + ": Killed!")
				p.Kill()
			}
		}
	}
}

func ruleSearch(eventName string) string {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(eventName + " " + strs)
			if err == nil && processSerch(strs) == true {
				return strs
			}
		}
	}

	return ""
}

func processSerch(processName string) bool {
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

func triggerChecker(ev uint32) bool {
	for _, x := range cliTriggers {
		if ev == x {
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
				if triggerChecker(ev.Mask) {
					debugLog("hit: " + ev.String())
					if strs := ruleSearch(ev.String()); len(strs) > 0 {
						sendClientMsg(stream, hitCmd, myIp+"\t"+strs)
					}
				}
			case err := <-watman.Error:
				log.Println("error:", err)
			}
		}
	}()
}

func loadConfig(trustFile string, tFlag bool) {
	loadOptions := ini.LoadOptions{}
	if tFlag == true {
		loadOptions.UnparseableSections = []string{"Trusts", "Rules", "Triggers", "TimeDecrement", "LogDir"}
		trusts = nil
		serverRules = nil
		svrTriggers = nil
	} else {
		loadOptions.UnparseableSections = []string{"Scores"}
		clients = nil
	}

	cfg, err := ini.LoadSources(loadOptions, trustFile)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	if tFlag == true {
		setStructs("Trusts", cfg.Section("Trusts").Body(), 0)
		setStructs("Rules", cfg.Section("Rules").Body(), 1)
		setStructs("Triggers", cfg.Section("Triggers").Body(), 3)
		setStructs("TimeDecrement", cfg.Section("TimeDecrement").Body(), 4)
		setStructs("LogDir", cfg.Section("LogDir").Body(), 5)
	} else {
		setStructs("Scores", cfg.Section("Scores").Body(), 2)
	}
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
				if len(strs) == 2 {
					if val, err := strconv.Atoi(strs[1]); err == nil {
						trusts = append(trusts, trustData{FILTER: strs[0], SCORE: val})
						debugLog(v)
					}
				}
			case 1:
				if len(strs) > 3 {
					var strr []string

					for i := 3; i < len(strs); i++ {
						strr = append(strr, strs[i])
					}

					if val, err := strconv.Atoi(strs[0]); err == nil {
						serverRules = append(serverRules, serverRuleData{SCORE: val, ACT: strs[1], EXEC: strs[2], CMDLINE: strr})
						debugLog(v)
					}
				}
			case 2:
				if len(strs) == 3 {
					if val, err := strconv.Atoi(strs[1]); err == nil {
						clients = append(clients, clientsData{IP: strs[0], SCORE: val, DETAIL: strs[2]})
						debugLog(v)
					}
				}
			case 4:
				if len(strs) == 2 {
					vala, erra := strconv.Atoi(strs[0])
					valb, errb := strconv.Atoi(strs[1])
					if erra == nil && errb == nil {
						TimeDecrement[0] = vala
						TimeDecrement[1] = valb
						debugLog(v)
					}
				}
			case 5:
			}
		} else if flag == 3 {
			svrTriggers = append(svrTriggers, v)
			debugLog(v)
		} else if flag == 5 {
			LogDir = v
			if Exists(LogDir) == false {
				if err := os.MkdirAll(LogDir, 0777); err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			}
			debugLog(v)
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
	filename := "goTrust_" + t.Format(layout) + ".log"

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

// FYI: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getIFandIP() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface.Name, ip.String(), nil
		}
	}
	return "", "", errors.New("are you connected to the network?")
}
