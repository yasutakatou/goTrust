/*
 * Zero Trust tool for Linux by Golang
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   Apache-2.0 License, BSD-3-Clause License
 */
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/process"

	//"github.com/subgraph/inotify"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"

	pb "yasutakatou/goTrust/proto"
)

//FYI: https://journal.lampetty.net/entry/capturing-stdout-in-golang
type Capturer struct {
	saved         *os.File
	bufferChannel chan string
	out           *os.File
	in            *os.File
}

type dataScoresData struct {
	SCORE int
	WORD  string
}

type trustData struct {
	FILTER string
	SCORE  int
}

type noTrustData struct {
	FILTER string
	CMD    string
}

type clientsData struct {
	IP     string
	DETAIL string
	SCORE  int
	Trust  bool
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

type responseData struct {
	response string
}

type apiData struct {
	Name     string
	Data     string
	Password string
}

const (
	reqCmd        = "requestClient"
	hitCmd        = "hitProcess"
	endRuleCmd    = "endRules"
	killCmd       = "killProcess"
	noTrustCmd    = "noTrust"
	trustCmd      = "okTrust"
	exitCmd       = "exitClient"
	addTriggerCmd = "addTrigger"
	pingCmd       = "hello"
	showCmd       = "show"
)

type filterData struct {
	IP    string
	Count int
}

var (
	debug, logging, noTrust, allowOverride                             bool
	trustFile, lockFile, LogDir, replaceStr, serverSecret, ApiPassword string
	openProcess                                                        []string
	trusts                                                             []trustData
	noTrusts                                                           []noTrustData
	clients                                                            []clientsData
	serverRules                                                        []serverRuleData
	clientRules                                                        []clientRuleData
	dataScores                                                         []dataScoresData
	svrTriggers                                                        []string
	cliTriggers                                                        []uint32
	TimeDecrement                                                      [2]int
	myIp                                                               string
	clientDisconnect                                                   int
	filterCount                                                        int
	filters                                                            []filterData
	allows                                                             []string
	dataScanCount                                                      int
)

func main() {
	_client := flag.Bool("client", false, "[-client=client mode (true is enable)]")
	_server := flag.String("server", "127.0.0.1:50005", "[-server=connect server (default: 127.0.0.1:50005)]")
	_secret := flag.String("secret", "goTrust", "[-secret=API allow secret]")
	_port := flag.String("port", ":50005", "[-port=server port (default: :50005)]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Rule := flag.String("rule", "rules.ini", "[-rule=rules config file]")
	_replaceStr := flag.String("replaceString", "{}", "[-replaceString= when no trust action, give ip paramater]")
	_Trust := flag.String("trust", "trust.ini", "[-trust=trusts config file)]")
	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")
	_Lock := flag.String("lock", "lock", "[-lock=lock file name and path]")
	_allowOverride := flag.Bool("allowOverride", false, "[-allowOverride=trust file override mode (true is enable)]")
	_clientDisconnect := flag.Int("clientDisconnect", 60, "[-clientDisconnect=client live interval ]")
	_filterCount := flag.Int("filterCount", 3, "[-filterCount=allow connect retrys.]")
	_dataScanCount := flag.Int("dataScanCount", 1000, "[-dataScanCount=data score count lines.]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path]")

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)
	lockFile = string(*_Lock)
	trustFile = string(*_Trust)
	replaceStr = string(*_replaceStr)
	allowOverride = bool(*_allowOverride)
	clientDisconnect = int(*_clientDisconnect)
	dataScanCount = int(*_dataScanCount)
	serverSecret = string(*_secret)
	filterCount = int(*_filterCount)

	if *_client == true {
		noTrust = false
		clientStart(*_server)
	} else {
		os.Remove(lockFile)
		serverStart(*_port, *_Rule, *_autoRW, *_cert, *_key)
	}

	for {
		fmt.Printf(".")
		time.Sleep(time.Second * time.Duration(1))
		if noTrust == true {
			noTrustMode()
		}
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
	recordOpenProcess()
	//scoresCounts

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
			if stra, datas := searchPath(resp.Cmd); stra != "" {
				strb := strings.Split(resp.Str, "\t")
				clientRules = append(clientRules, clientRuleData{EXEC: stra, CMDLINE: strb, NOPATH: resp.Cmd})
				sendClientMsg(stream, showCmd, intStructToString(datas))
			}
		}
	}

	nowTime := time.Now().Unix()

	go func() {
		for {
			now := time.Now()
			if now.Unix()+int64(clientDisconnect) > nowTime {
				debugLog("[server missing.. no trust mode!]")
				noTrust = true
			}

			resp, err := stream.Recv()
			if err != nil {
				log.Fatalf("can not receive %v", err)
				os.Exit(1)
			}
			if resp.Cmd != trustCmd {
				debugLog("recv: " + resp.Cmd + " " + resp.Str)
			}

			switch resp.Cmd {
			case killCmd:
				killProcessName(resp.Str)
			case exitCmd:
				stream.CloseSend()
				debugLog("add client failed..")
				os.Exit(1)
			case noTrustCmd:
				debugLog("[no trust mode!]")
				noTrust = true
			case trustCmd:
				if noTrust == true {
					debugLog("[retrust!]")
					nowTime = time.Now().Unix()
				}
				noTrust = false
			}
		}
	}()

	if len(clientRules) > 0 {
		setWatch(stream)
	} else {
		fmt.Println("rules not found..")
		os.Exit(1)
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

func intStructToString(str []int) string {
	result := ""
	for _, ints := range str {
		result = result + strconv.Itoa(ints)
	}
	return result
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
				case pingCmd:
					if scoreSearch(req.Str) == false {
						sendServerMsg(srv, noTrustCmd, "")
						if trustSwitch(req.Str) == true {
							noTrustExec(req.Str)
						}
					} else {
						sendServerMsg(srv, trustCmd, "")
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

func trustSwitch(ip string) bool {
	for x, client := range clients {
		if client.IP == ip {
			if client.Trust == true {
				clients[x].Trust = false
				return true
			}
		}
	}
	return false
}

func scoreSearch(ip string) bool {
	for _, client := range clients {
		if client.IP == ip {
			if client.SCORE == 0 {
				return false
			} else {
				return true
			}
		}
	}
	return true
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
				clients = append(clients, clientsData{IP: ips[0], SCORE: rule.SCORE, DETAIL: ips[1], Trust: true})
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
			if len(clients[i].IP) > 7 {
				convInt := strconv.Itoa(clients[i].SCORE)
				_, err = file.WriteString(clients[i].IP + "\t" + convInt + "\t" + clients[i].DETAIL)
			}
		}

		time.Sleep(time.Second * time.Duration(1))

		if err := os.Remove(lockFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}
}

func actRules(srv pb.Logging_LogServer, act string) bool {
	acts := strings.Split(act, "\t")
	for i := 0; i < len(serverRules); i++ {
		for _, CMD := range serverRules[i].CMDLINE {
			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && CMD == "*" {
				exportLog(acts[0], serverRules[i], decrementScore(srv, acts[0], serverRules[i].SCORE))
				return true
			}

			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && strings.Index(acts[1], CMD) != -1 {
				exportLog(acts[0], serverRules[i], decrementScore(srv, acts[0], serverRules[i].SCORE))
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

func decrementScore(srv pb.Logging_LogServer, ip string, score int) int {
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

func serverStart(port, config string, autoRW bool, cert, key string) {
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

	http.HandleFunc("/api", apiHandler)
	err := http.ListenAndServeTLS(":50006", cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
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
				if clients[i].Trust == true {
					fmt.Printf("[O] IP: %s Score: %d Detail: %s\n", clients[i].IP, clients[i].SCORE, clients[i].DETAIL)
				} else {
					fmt.Printf("[X] IP: %s Score: %d Detail: %s\n", clients[i].IP, clients[i].SCORE, clients[i].DETAIL)
				}
			}
			exportClients()
		}
	}()

	// and start...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if debug == true {
		fmt.Println("put call: ", r.RemoteAddr, r.URL.Path)
	}

	var data *responseData
	var outputJson []byte

	if len(allows) > 0 {
		if checkAllows(r.RemoteAddr) == false {
			debugLog(r.RemoteAddr + ": not allow!")
			data = &responseData{response: "error " + r.RemoteAddr + " not allow!"}
			outputJson, _ = json.Marshal(data)
			w.Write(outputJson)
			return
		}
	}

	d := json.NewDecoder(r.Body)
	p := &apiData{}
	err := d.Decode(p)
	if err != nil {
		w.Write([]byte("internal server error"))
		return
	}

	debugLog("api PUT) Name: " + p.Name + " Data: " + p.Data + " Password: " + p.Password)

	if p.Password == ApiPassword {
		resp := apiDo(r.RemoteAddr, p)
		if resp == "" {
			addRetrys(r.RemoteAddr)
		} else {
			resetRetry(r.RemoteAddr)
		}
		data = &responseData{response: resp}
	} else {
		if checkRetrys(r.RemoteAddr) == false {
			debugLog(r.RemoteAddr + ": over retrys")
			data = &responseData{response: "error " + r.RemoteAddr + " : over retrys"}
		} else {
			data = &responseData{response: "error " + r.RemoteAddr + " : password invalid"}
		}
	}

	outputJson, err = json.Marshal(data)
	if err != nil {
		w.Write([]byte("internal server error"))
		return
	}

	w.Write(outputJson)
}

func resetRetry(ipp string) {
	ip := strings.Split(ipp, ":")[0]
	for x, fil := range filters {
		if fil.IP == ip {
			filters[x].Count = 0
		}
	}
}

func addRetrys(ipp string) {
	ip := strings.Split(ipp, ":")[0]
	for x, fil := range filters {
		if fil.IP == ip {
			filters[x].Count = filters[x].Count + 1
		}
	}
}

func checkRetrys(ipp string) bool {
	ip := strings.Split(ipp, ":")[0]
	for x, fil := range filters {
		if fil.IP == ip {
			if fil.Count >= filterCount {
				return false
			}
			filters[x].Count = filters[x].Count + 1
			return true
		}
	}

	filters = append(filters, filterData{IP: ip, Count: 1})
	return true
}

func checkAllows(ip string) bool {
	for _, allow := range allows {
		ipRegex := regexp.MustCompile(allow)
		if ipRegex.MatchString(ip) == true {
			return true
		}
	}
	return false
}

func apiDo(ipp string, apiCall *apiData) string {
	ip := strings.Split(ipp, ":")[0]
	switch apiCall.Name {
	case "score":
		if len(apiCall.Data) > 2 {
			switch apiCall.Data[0:1] {
			case "+":
				i, err := strconv.Atoi(apiCall.Data[1:])
				if err != nil {
					return ""
				}
				scoreControl(ip, true, i)
				exportClients()
			case "-":
				i, err := strconv.Atoi(apiCall.Data[1:])
				if err != nil {
					return ""
				}
				scoreControl(ip, false, i)
				exportClients()
			default:
				return ""
			}
		}
		return ""
	case "show":
	default:
		return ""
	}
	return ""
}

func scoreControl(ip string, plusMinus bool, cnt int) {
	for x, client := range clients {
		if client.IP == ip {
			if plusMinus == true {
				clients[x].SCORE = clients[x].SCORE + cnt
			} else {
				if client.SCORE-cnt < 0 {
					clients[x].SCORE = 0
				} else {
					clients[x].SCORE = clients[x].SCORE - cnt
				}
			}
		}
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

func recordOpenProcess() {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(eventName + " " + strs)
			if err == nil {
				openProcess = append(openProcess, strs)
			}
		}
	}
}

func noTrustMode() {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(eventName + " " + strs)
			if err == nil && openProcessSerch(strs) == false {
				debugLog(strs + ": no trust! Killed!!")
				p.Kill()
			}
		}
	}
}

func openProcessSerch(pStr string) bool {
	for _, p := range openProcess {
		if pStr == p {
			return true
		}
	}
	return false
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

	go func() {
		for {
			sendClientMsg(stream, pingCmd, myIp)
			time.Sleep(time.Second * time.Duration(1))
		}
	}()

}

func loadConfig(trustFile string, tFlag bool) {
	loadOptions := ini.LoadOptions{}
	if tFlag == true {
		loadOptions.UnparseableSections = []string{"Trusts", "Rules", "Triggers", "TimeDecrement", "LogDir", "noTrusts", "ApiPassword", "AllowIP", "dataScore"}
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
		setStructs("noTrusts", cfg.Section("noTrusts").Body(), 6)
		setStructs("ApiPassword", cfg.Section("ApiPassword").Body(), 7)
		setStructs("AllowIP", cfg.Section("AllowIP").Body(), 8)
		setStructs("dataScore", cfg.Section("dataScore").Body(), 9)
	} else {
		setStructs("Scores", cfg.Section("Scores").Body(), 2)
	}
}

func searchPath(filename string) (string, []int) {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, cmd := range paths {
		if Exists(cmd + "/" + filename) {
			debugLog("Command Exists! : " + cmd + "/" + filename)
			return cmd + "/" + filename, nil
		}
	}

	if Exists(filename) {
		debugLog("File Exists! : " + filename)
		datas := scanDataScore(filename)
		return filename, datas
	}

	debugLog("Not Exists! : " + filename)
	return "", nil
}

func scanDataScore(filename string) []int {
	count := 0
	datas := make([]int, len(dataScores))

	var fp *os.File
	var err error

	fp, err = os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return datas
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		if count > dataScanCount {
			break
		}
		readData := scanner.Text()
		sct := scanStr(readData)
		if sct > 0 {
			datas[sct-1] = datas[sct-1] + dataScores[sct-1].SCORE
		}
		count = count + 1
	}
	return datas
}

func scanStr(readStr string) int {
	for x, datas := range dataScores {
		strRegex := regexp.MustCompile(datas.WORD)
		if strRegex.MatchString(readStr) == true {
			return x + 1
		}
	}
	return 0
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
						if val == 0 {
							clients = append(clients, clientsData{IP: strs[0], SCORE: val, DETAIL: strs[2], Trust: false})
						} else {
							clients = append(clients, clientsData{IP: strs[0], SCORE: val, DETAIL: strs[2], Trust: true})
						}
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
			case 6:
				if len(strs) == 2 {
					noTrusts = append(noTrusts, noTrustData{FILTER: strs[0], CMD: strs[1]})
					debugLog(v)
				}
			case 9:
				if len(strs) == 2 {
					if val, err := strconv.Atoi(strs[0]); err == nil {
						dataScores = append(dataScores, dataScoresData{SCORE: val, WORD: strs[1]})
						debugLog(v)
					}
				}
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
		} else if flag == 7 {
			ApiPassword = v
			debugLog(v)
		} else if flag == 8 {
			allows = append(allows, v)
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

func noTrustExec(ip string) {
	for _, rule := range noTrusts {
		ipRegex := regexp.MustCompile(rule.FILTER)
		if ipRegex.MatchString(ip) == true {
			cmdExec(rule.CMD, ip)
		}
	}
}

func cmdExec(command, ip string) {
	var cmd *exec.Cmd
	var out string

	command = strings.Replace(command, replaceStr, ip, 1)
	debugLog("command: " + command)

	cmd = exec.Command(os.Getenv("SHELL"), "-c", command)

	c := &Capturer{}
	c.StartCapturingStdout()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()

	out = c.StopCapturingStdout()

	debugLog(out)
}

// 標準出力をキャプチャする
func (c *Capturer) StartCapturingStdout() {
	c.saved = os.Stdout
	var err error
	c.in, c.out, err = os.Pipe()
	if err != nil {
		panic(err)
	}

	os.Stdout = c.out
	c.bufferChannel = make(chan string)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, c.in)
		c.bufferChannel <- b.String()
	}()
}

// キャプチャを停止する
func (c *Capturer) StopCapturingStdout() string {
	c.out.Close()
	os.Stdout = c.saved
	return <-c.bufferChannel
}
