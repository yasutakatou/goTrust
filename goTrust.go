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
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/process"

	"google.golang.org/grpc"
	"gopkg.in/ini.v1"

	"yasutakatou/goTrust/fwatcher"
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
	SCORE string
	WORD  string
}

type clientScoresData struct {
	IP     string
	Scores string
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

type responseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type apiData struct {
	Name     string `json:"name"`
	Data     string `json:"data"`
	Password string `json:"password"`
}

const (
	reqCmd         = "requestClient"
	hitCmd         = "hitProcess"
	endRuleCmd     = "endRules"
	killCmd        = "killProcess"
	noTrustCmd     = "noTrust"
	trustCmd       = "okTrust"
	exitCmd        = "exitClient"
	addTriggerCmd  = "addTrigger"
	pingCmd        = "hello"
	showCmd        = "show"
	authCmd        = "auth"
	addScoreCmd    = "addScore"
	resetClientCmd = "reset"
	setServerCmd   = "server"
	scoreAddCmd    = "scoreAdd"
	scoreCtlCmd    = "scoreCtl"
)

type requestData struct {
	Token string `json:"token"`
}

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
	clientRules                                                        []fwatcher.ClientRuleData
	dataScores                                                         []dataScoresData
	clientScores                                                       []clientScoresData
	svrTriggers                                                        []string
	cliTriggers                                                        []uint32
	TimeDecrement                                                      [2]int
	myIp                                                               string
	clientDisconnect                                                   int
	filterCount                                                        int
	filters                                                            []filterData
	allows                                                             []string
	dataScanCount                                                      int
	resetClient                                                        chan bool
	nowTime                                                            int64
)

func main() {
	_client := flag.Bool("client", false, "[-client=client mode (true is enable)]")
	_server := flag.String("server", "127.0.0.1:50005", "[-server=connect server (default: 127.0.0.1:50005)]")
	_secret := flag.String("secret", "goTrust", "[-secret=API allow secret]")
	_grpc := flag.String("grpc", ":50005", "[-grpc=grpc port (default: :50005)]")
	_api := flag.String("api", ":50006", "[-api=api port (default: :50006)]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Rule := flag.String("rule", "./rules.ini", "[-rule=rules config file]")
	_replaceStr := flag.String("replaceString", "{}", "[-replaceString= when no trust action, give ip paramater]")
	_Trust := flag.String("trust", "./trust.ini", "[-trust=trusts config file)]")
	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")
	_Lock := flag.String("lock", "lock", "[-lock=lock file name and path]")
	_allowOverride := flag.Bool("allowOverride", false, "[-allowOverride=trust file override mode (true is enable)]")
	_clientDisconnect := flag.Int("clientDisconnect", 60, "[-clientDisconnect=client live interval ]")
	_filterCount := flag.Int("filterCount", 3, "[-filterCount=allow connect retrys.]")
	_dataScanCount := flag.Int("dataScanCount", 1000, "[-dataScanCount=data score count lines.]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path]")
	_ApiPassword := flag.String("ApiPassword", "goTrust", "[-secret=api password]")

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
	ApiPassword = string(*_ApiPassword)

	if *_client == true {
		noTrust = false
		clientStart(*_server, *_api)
	} else {
		os.Remove(lockFile)
		serverStart(*_grpc, *_Rule, *_autoRW, *_cert, *_key, *_api)
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
	//fwatcher.DebugLog("sendClientMsg Command: " + cmd + " String: " + str)
	req := pb.Request{Cmd: cmd, Str: str}
	if err := stream.Send(&req); err != nil {
		fmt.Printf("client missing! can not send %v\n", err)
		//os.Exit(1)
	}
}

func sendServerMsg(stream pb.Logging_LogServer, cmd, str string) {
	req := pb.Response{Cmd: cmd, Str: str}
	if err := stream.Send(&req); err != nil {
		fmt.Printf("server missing! can not send %v\n", err)
		//os.Exit(1)
	} else {
		nowTime = time.Now().Unix()
	}
}

func clientStart(server, api string) {
	recordOpenProcess()

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
		fmt.Println(err)
		os.Exit(1)
	}
	myIp = ip

	sendClientMsg(stream, reqCmd, myIp+"\t"+uname())

	initClient(stream, api)

	nowTime = time.Now().Unix()
	retryFlag := false

	go func() {
		for {
			now := time.Now()
			if now.Unix() > nowTime+int64(clientDisconnect) && retryFlag == true {
				fwatcher.DebugLog("[server missing.. no trust mode!]", logging, debug)
				noTrust = true
				time.Sleep(time.Second * time.Duration(3))
			}

			if now.Unix() > nowTime+int64(5) && retryFlag == true {
				fwatcher.DebugLog("[retry connect!]", logging, debug)
				time.Sleep(time.Second * time.Duration(3))
				conn, err = grpc.Dial(server, grpc.WithInsecure())
				if err != nil {
					fmt.Println(err)
					fwatcher.DebugLog("can not connect with server: "+server, logging, debug)
				} else {
					client = pb.NewLoggingClient(conn)
					stream, err = client.Log(context.Background())
					if err != nil {
						fwatcher.DebugLog("open stream error", logging, debug)
					} else {
						fwatcher.DebugLog("[retry success!]", logging, debug)
						ctx = stream.Context()
						retryFlag = false

						fwatcher.ResetTrue()
						fwatcher.DebugLog("watcher resetting..", logging, debug)
						time.Sleep(time.Second * time.Duration(3))
						fwatcher.SetWatch(stream, clientRules, myIp, cliTriggers, logging, debug)
					}
				}
			}

			if retryFlag == false {
				resp, err := stream.Recv()
				if err != nil {
					retryFlag = true
				} else {
					if resp.Cmd != trustCmd && fwatcher.ResetCheck() == false {
						fwatcher.DebugLog("recv: "+resp.Cmd+" "+resp.Str, logging, debug)
					}

					switch resp.Cmd {
					case resetClientCmd:
						fwatcher.ResetTrue()
						fwatcher.DebugLog("client resetting..", logging, debug)
						time.Sleep(time.Second * time.Duration(3))
						initClient(stream, api)
						if len(clientRules) > 0 {
							fwatcher.SetWatch(stream, clientRules, myIp, cliTriggers, logging, debug)
						} else {
							fmt.Println("rules not found..")
							os.Exit(1)
						}
					case killCmd:
						killProcessName(resp.Str)
					case exitCmd:
						stream.CloseSend()
						fwatcher.DebugLog("add client failed..", logging, debug)
						os.Exit(1)
					case noTrustCmd:
						fwatcher.DebugLog("[no trust mode!]", logging, debug)
						noTrust = true
					case trustCmd:
						if noTrust == true {
							fwatcher.DebugLog("[retrust!]", logging, debug)
							nowTime = time.Now().Unix()
						}
						noTrust = false
					}
				}
			}
		}
	}()

	if len(clientRules) > 0 {
		fwatcher.SetWatch(stream, clientRules, myIp, cliTriggers, logging, debug)
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

func JsonToByte(data apiData) []byte {
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func initClient(stream pb.Logging_LogClient, api string) {
	var server string

	clientRules = nil
	dataScores = nil

	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("can not receive %v", err)
			os.Exit(1)
		}

		if resp.Cmd == endRuleCmd {
			break
		}

		fwatcher.DebugLog("resp Command: "+resp.Cmd+" String: "+resp.Str, logging, debug)

		switch resp.Cmd {
		case authCmd:
			sendClientMsg(stream, authCmd, ApiPassword)
		case exitCmd:
			stream.CloseSend()
			fwatcher.DebugLog("add client failed..", logging, debug)
			os.Exit(1)
		case addTriggerCmd:
			if val, err := strconv.ParseUint(resp.Str, 10, 32); err == nil {
				cliTriggers = append(cliTriggers, uint32(val))
			} else {
				fmt.Println(err)
			}
		case addScoreCmd:
			strb := strings.Split(resp.Str, "\t")
			dataScores = append(dataScores, dataScoresData{SCORE: strb[0], WORD: strb[1]})
		case setServerCmd:
			server = resp.Str
			fwatcher.DebugLog("Server: "+server, logging, debug)
		default:
			if cnt, stra, datas := searchPath(resp.Cmd); cnt != 0 {
				strb := strings.Split(resp.Str, "\t")
				clientRules = append(clientRules, fwatcher.ClientRuleData{EXEC: stra, CMDLINE: strb, NOPATH: resp.Cmd})
				if cnt == 2 {

					fwatcher.DebugLog("data source: "+stra+" score: "+intStructToString(datas), logging, debug)
					_, ip, err := getIFandIP()
					if err == nil {
						sendServerHttp(server+api, scoreAddCmd, ip+"\t"+intStructToString(datas), ApiPassword)
					}
				}
			}
		}
	}

}

func sendServerHttp(ip, path, data, password string) {
	fwatcher.DebugLog("send: "+ip+" data: "+data+" password:"+password, logging, debug)

	if strings.Index(ip, "https://") == -1 {
		ip = "https://" + ip + "/api"
	}

	request, err := http.NewRequest(
		"POST",
		ip,
		bytes.NewBuffer(JsonToByte(apiData{Name: path, Data: data, Password: password})),
	)

	if err != nil {
		fmt.Println(err)
	}

	request.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	fwatcher.DebugLog("response: "+string(body), logging, debug)
}

func intStructToString(str []int) string {
	result := ""
	for x, ints := range str {
		cnt := strconv.Itoa(ints)
		if cnt == "" {
			result = result + dataScores[x].WORD + "0,"

		} else {
			result = result + dataScores[x].WORD + " " + cnt + ","
		}
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
				if fwatcher.ResetCheck() == true {
					sendServerMsg(srv, resetClientCmd, "")
					fwatcher.DebugLog("send reset. resetting rules..", logging, debug)
					respRules(srv)
					fwatcher.ResetFalse()
				}

				switch req.Cmd {
				case authCmd:
					if req.Str != ApiPassword {
						sendServerMsg(srv, exitCmd, "password invaid")
					}
				case reqCmd:
					if checkAllows(req.Str) == false {
						fwatcher.DebugLog(req.Str+": not allow!", logging, debug)
						sendServerMsg(srv, exitCmd, "")
					} else {
						if addClient(req.Str) == true {
							respRules(srv)
						} else {
							fwatcher.DebugLog("no match client rule: "+req.Str, logging, debug)
							sendServerMsg(srv, exitCmd, "")
						}

					}
				case hitCmd:
					if act := actRules(srv, req.Str); act > 0 {
						if act == 1 {
							sendServerMsg(srv, killCmd, strings.Split(req.Str, "\t")[1])
						}
					}
				case pingCmd:
					//fwatcher.DebugLog("server pong!", logging, debug)
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

func addClientDataScore(ip, strs string) {
	for _, client := range clientScores {
		if ip == client.IP {
			clientScores = append(clientScores, clientScoresData{IP: ip, Scores: strs})
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
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return hostname
}

func addClient(ip string) bool {
	ride := 0
	ips := strings.Split(ip, "\t")
	for x, client := range clients {
		if client.IP == ips[0] {
			if allowOverride == false {
				fwatcher.DebugLog("clients exsits: "+ips[0], logging, debug)
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
				fwatcher.DebugLog("override client: "+ips[0]+" "+uname(), logging, debug)
			} else {
				clients = append(clients, clientsData{IP: ips[0], SCORE: rule.SCORE, DETAIL: ips[1], Trust: true})
				fwatcher.DebugLog("add client: "+ips[0]+" "+uname(), logging, debug)
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

func actRules(srv pb.Logging_LogServer, act string) int {
	//0: no action 1: kill 2: no kill
	acts := strings.Split(act, "\t")
	for i := 0; i < len(serverRules); i++ {
		for _, CMD := range serverRules[i].CMDLINE {
			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && CMD == "*" {
				exportLog(acts[0], serverRules[i], decrementScore(srv, acts[0], serverRules[i].SCORE))
				if serverRules[i].ACT == "KILL" {
					return 1
				}
				return 2
			}

			if strings.Index(acts[1], serverRules[i].EXEC) != -1 && strings.Index(acts[1], CMD) != -1 {
				exportLog(acts[0], serverRules[i], decrementScore(srv, acts[0], serverRules[i].SCORE))
				if serverRules[i].ACT == "KILL" {
					return 1
				}
				return 2
			}
		}
	}
	return 0
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
		fmt.Println(err)
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
	sendServerMsg(srv, authCmd, "")

	_, ip, err := getIFandIP()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	sendServerMsg(srv, setServerCmd, ip)

	for _, rule := range svrTriggers {
		sendServerMsg(srv, addTriggerCmd, rule)
	}

	for _, rule := range dataScores {
		sendServerMsg(srv, addScoreCmd, rule.SCORE+"\t"+rule.WORD)
	}

	for _, rule := range serverRules {
		sendServerMsg(srv, rule.EXEC, concatTab(rule.CMDLINE))
	}

	sendServerMsg(srv, endRuleCmd, "")
}

func serverStart(port, config string, autoRW bool, cert, key, api string) {
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

		//creates a new file watcher
		trust, err := fsnotify.NewWatcher()
		if err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
		defer trust.Close()

		go func() {
			for {
				select {
				case <-watcher.Events:
					time.Sleep(time.Second * time.Duration(1))
					if Exists(lockFile) == false {
						loadConfig(config, true)
					}
				case <-watcher.Errors:
					fmt.Println("ERROR", err)
					os.Exit(1)
				}
			}
		}()

		go func() {
			for {
				select {
				case <-trust.Events:
					time.Sleep(time.Second * time.Duration(1))
					if Exists(lockFile) == false {
						loadConfig(trustFile, false)
					}
				case <-trust.Errors:
					fmt.Println("ERROR", err)
					os.Exit(1)
				}
			}
		}()

		if err := watcher.Add(config); err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}

		if err := trust.Add(trustFile); err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
	}

	go func() {
		http.HandleFunc("/api", apiHandler)
		err := http.ListenAndServeTLS(api, cert, key, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
			os.Exit(1)
		}
	}()

	// create listiner
	lis, err := net.Listen("tcp", ":50005")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
		os.Exit(1)
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
		os.Exit(1)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	fwatcher.DebugLog("put call: "+r.RemoteAddr+" path: "+r.URL.Path, logging, debug)

	var data *responseData
	var outputJson []byte

	if len(allows) > 0 {
		if checkAllows(r.RemoteAddr) == false {
			fwatcher.DebugLog(r.RemoteAddr+": not allow!", logging, debug)
			data = &responseData{Status: "Error", Message: r.RemoteAddr + " not allow!"}
			outputJson, _ = json.Marshal(data)
			w.Write(outputJson)
			return
		}
	}

	d := json.NewDecoder(r.Body)
	p := &apiData{}
	err := d.Decode(p)
	if err != nil {
		data = &responseData{Status: "Error", Message: "internal server error"}
		outputJson, _ = json.Marshal(data)
		w.Write(outputJson)
		return
	}

	fwatcher.DebugLog("api PUT) Name: "+p.Name+" Data: "+p.Data+" Password: "+p.Password, logging, debug)

	if p.Password == ApiPassword && checkRetrys(r.RemoteAddr) == true {
		resp := apiDo(p)
		if resp == "" {
			data = &responseData{Status: "Error", Message: "invalid api call"}
			addRetrys(r.RemoteAddr)
		} else {
			data = &responseData{Status: "Success", Message: resp}
			resetRetry(r.RemoteAddr)
		}
	} else {
		if checkRetrys(r.RemoteAddr) == false {
			fwatcher.DebugLog(r.RemoteAddr+": over retrys", logging, debug)
			data = &responseData{Status: "Error", Message: r.RemoteAddr + " : over retrys"}
		} else {
			data = &responseData{Status: "Error", Message: r.RemoteAddr + " : password invalid"}
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

func apiDo(apiCall *apiData) string {
	switch apiCall.Name {
	case scoreAddCmd:
		scoreAdd(apiCall.Data)
		return "add " + apiCall.Data
	case scoreCtlCmd:
		ip := strings.Split(apiCall.Data, ",")
		if len(apiCall.Data) > 2 {
			switch ip[0][0:1] {
			case "+":
				i, err := strconv.Atoi(ip[0][1:])
				if err != nil {
					fmt.Println(err)
					return ""
				}
				if scoreControl(ip[1], true, i) == true {
					exportClients()
					return "calc " + apiCall.Data
				}
			case "-":
				i, err := strconv.Atoi(ip[0][1:])
				if err != nil {
					fmt.Println(err)
					return ""
				}
				if scoreControl(ip[1], false, i) == true {
					exportClients()
					return "calc " + apiCall.Data
				}
			default:
				return ""
			}
		}
		return ""
	case resetClientCmd:
		if resp := checkClient(apiCall.Data); resp != "" {
			fwatcher.ResetTrue()
			return "reset\t" + resp
		}
	case showCmd:
		fwatcher.DebugLog("target: "+apiCall.Data, logging, debug)
		if resp := searchClients(apiCall.Data); resp != "" {
			return resp
		}
	default:
		return ""
	}
	return ""
}

func checkClient(data string) string {
	for _, client := range clientScores {
		if client.IP == data {
			return data
		}
	}
	return ""
}

func scoreAdd(datas string) {
	data := strings.Split(datas, "\t")
	for x, client := range clientScores {
		if client.IP == data[0] {
			clientScores[x].Scores = clientScores[x].Scores + "," + data[1]
		}
	}

	clientScores = append(clientScores, clientScoresData{IP: data[0], Scores: data[1]})
}

func searchClients(ip string) string {
	for _, client := range clientScores {
		//fwatcher.DebugLog("IP: " + client.IP + " SCORE: " + client.Scores, logging, debug)
		if ip == client.IP {
			return client.Scores
		}
	}
	return ""
}

func scoreControl(ip string, plusMinus bool, cnt int) bool {
	for x, client := range clients {
		if client.IP == ip {
			if plusMinus == true {
				clients[x].SCORE = clients[x].SCORE + cnt
				return true
			} else {
				if client.SCORE-cnt < 0 {
					clients[x].SCORE = 0
					return true
				} else {
					clients[x].SCORE = clients[x].SCORE - cnt
					return true
				}
			}
		}
	}
	return false
}

func recordOpenProcess() {
	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		for _, p := range processes {
			strs, err := p.Cmdline()
			//log.Println(strs)
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
				fwatcher.DebugLog(strs+": no trust! Killed!!", logging, debug)
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
			if err == nil && fwatcher.ProcessSerch(strs, clientRules) == true {
				fwatcher.DebugLog(strs+": Killed!", logging, debug)
				p.Kill()
			}
		}
	}
}

func loadConfig(trustFile string, tFlag bool) {
	lfile, err := os.Create(lockFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	lfile.Close()

	loadOptions := ini.LoadOptions{}
	if tFlag == true {
		loadOptions.UnparseableSections = []string{"Trusts", "Rules", "Triggers", "TimeDecrement", "LogDir", "noTrusts", "ApiPassword", "AllowIP", "dataScore"}
		trusts = nil
		serverRules = nil
		svrTriggers = nil
		dataScores = nil
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
		setStructs("AllowIP", cfg.Section("AllowIP").Body(), 7)
		setStructs("dataScore", cfg.Section("dataScore").Body(), 8)
	} else {
		setStructs("Scores", cfg.Section("Scores").Body(), 2)
	}

	os.Remove(lockFile)
}

func searchPath(filename string) (int, string, []int) {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, cmd := range paths {
		if Exists(cmd + "/" + filename) {
			fwatcher.DebugLog("Command Exists! : "+cmd+"/"+filename, logging, debug)
			return 1, cmd + "/" + filename, nil
		}
	}

	if Exists(filename) {
		fwatcher.DebugLog("File Exists! : "+filename, logging, debug)
		datas := scanDataScore(filename)
		return 2, filename, datas
	}

	fwatcher.DebugLog("Not Exists! : "+filename, logging, debug)
	return 0, "", nil
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
			if val, err := strconv.Atoi(dataScores[sct-1].SCORE); err == nil {
				datas[sct-1] = datas[sct-1] + val
			}
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
	fwatcher.DebugLog(" -- "+configType+" --", logging, debug)

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if strings.Index(v, "\t") != -1 {
			strs := strings.Split(v, "\t")

			switch flag {
			case 0:
				if len(strs) == 2 {
					if val, err := strconv.Atoi(strs[1]); err == nil {
						trusts = append(trusts, trustData{FILTER: strs[0], SCORE: val})
						fwatcher.DebugLog(v, logging, debug)
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
						fwatcher.DebugLog(v, logging, debug)
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
						fwatcher.DebugLog(v, logging, debug)
					}
				}
			case 4:
				if len(strs) == 2 {
					vala, erra := strconv.Atoi(strs[0])
					valb, errb := strconv.Atoi(strs[1])
					if erra == nil && errb == nil {
						TimeDecrement[0] = vala
						TimeDecrement[1] = valb
						fwatcher.DebugLog(v, logging, debug)
					}
				}
			case 6:
				if len(strs) == 2 {
					noTrusts = append(noTrusts, noTrustData{FILTER: strs[0], CMD: strs[1]})
					fwatcher.DebugLog(v, logging, debug)
				}
			case 8:
				if len(strs) == 2 {
					dataScores = append(dataScores, dataScoresData{SCORE: strs[0], WORD: strs[1]})
					fwatcher.DebugLog(v, logging, debug)
				}
			}
		} else if flag == 3 {
			strVal := v
			if strings.Index(strVal, "0x") == 0 {
				tmpVal, err := strconv.ParseInt(strings.Replace(strVal, "0x", "", 1), 16, 32)
				if err == nil {
					strVal := strconv.FormatInt(tmpVal, 16)
					svrTriggers = append(svrTriggers, strVal)
					fwatcher.DebugLog(strVal, logging, debug)
				}
			} else {
				svrTriggers = append(svrTriggers, strVal)
				fwatcher.DebugLog(strVal, logging, debug)
			}
		} else if flag == 5 {
			LogDir = v
			if Exists(LogDir) == false {
				if err := os.MkdirAll(LogDir, 0777); err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			}
			fwatcher.DebugLog(v, logging, debug)
		} else if flag == 7 {
			allows = append(allows, v)
			fwatcher.DebugLog(v, logging, debug)
		}
	}
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
	fwatcher.DebugLog("command: "+command, logging, debug)

	cmd = exec.Command(os.Getenv("SHELL"), "-c", command)

	c := &Capturer{}
	c.StartCapturingStdout()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()

	out = c.StopCapturingStdout()

	fwatcher.DebugLog(out, logging, debug)
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
