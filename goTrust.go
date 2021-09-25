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
	reqCmd     = "requestClient"
	hitCmd     = "hitProcess"
	endRuleCmd = "endRules"
	killCmd    = "killProcess"
	noTrustCmd = "noTrust"
	reTrustCmd = "reTrust"
	exitCmd    = "exitClient"
)

var (
	debug, logging, noTrust bool
	trustFile, lockFile     string
	trusts                  []trustData
	clients                 []clientsData
	serverRules             []serverRuleData
	clientRules             []clientRuleData
	triggers                = []uint32{0x1, 0x40000001}
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

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)
	lockFile = string(*_Lock)
	trustFile = string(*_Trust)

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

	sendClientMsg(stream, reqCmd, ip+"\t"+uname())
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
			}
		}
	}

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
						sendServerMsg(srv, killCmd, req.Str)
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
	ips := strings.Split(ip, "\t")
	fmt.Println(ips)
	for _, client := range clients {
		fmt.Println(client)
		if client.IP == ips[0] {
			debugLog("clients exsits: " + ips[0])
			return false
		}
	}
	for _, rule := range trusts {
		ipRegex := regexp.MustCompile(rule.FILTER)
		if ipRegex.MatchString(ips[0]) == true {
			clients = append(clients, clientsData{IP: ips[0], SCORE: rule.SCORE, DETAIL: ips[1]})
			debugLog("add client: " + ips[0] + " " + uname())
			exportClients(lockFile, trustFile)
			return true
		}
	}
	return false
}

func exportClients(lockFile, trustFile string) {
	if Exists(lockFile) == false {
		lfile, err := os.Create(lockFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		lfile.Close()

		const layout = "2006-01-02_15"
		t := time.Now()
		if err := os.Rename(trustFile, trustFile+"_"+t.Format(layout)); err != nil {
			fmt.Println(err)
			return
		}

		file, err := os.Create(trustFile)
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

		if err := os.Remove(lockFile); err != nil {
			fmt.Println(err)
		}
		return
	}
}

func actRules(srv pb.Logging_LogServer, act string) bool {
	for i := 0; i < len(serverRules); i++ {
		for _, CMD := range serverRules[i].CMDLINE {
			if strings.Index(act, serverRules[i].EXEC) != -1 && CMD == "*" {
				return true
			}

			if strings.Index(act, serverRules[i].EXEC) != -1 && strings.Index(act, CMD) != -1 {
				return true
			}
		}
	}
	return false
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

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	defer watcher.Close()

	if autoRW == true {
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
	}

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

	if autoRW == true {
		go func() {
			for {
				select {
				case <-trust.Events:
					loadConfig(trustFile, false)
				case <-trust.Errors:
					fmt.Println("ERROR", err)
					os.Exit(1)
				}
			}
		}()
	}

	if err := trust.Add(trustFile); err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
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
	for _, x := range triggers {
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
						sendClientMsg(stream, hitCmd, strs)
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
		loadOptions.UnparseableSections = []string{"Trusts", "Rules"}
		serverRules = nil
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
	} else {
		setStructs("Scores", cfg.Section("Scores").Body(), 3)
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
			case 3:
				if len(strs) == 3 {
					if val, err := strconv.Atoi(strs[1]); err == nil {
						clients = append(clients, clientsData{IP: strs[0], SCORE: val, DETAIL: strs[2]})
						debugLog(v)
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
