package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"github.com/YuSitong1999/gremlinproxy/config"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	str "strings"
	"sync"
	"time"
)

var proxylog = config.ProxyLogger
var globallog = config.GlobalLogger

// Proxy implements the proxying logic between a pair of services.
// A single router can have multiple proxies, one for each service that the local service needs to talk to
// 实现一对服务之间的代理逻辑。
// 一个路由器可以有多个代理，本地服务需要与之对话的每个服务对应一个代理
type Proxy struct {
	name       string
	testid     string
	port       uint16
	bindhost   string
	Protocol   string
	rules      map[MessageType][]Rule
	ruleLock   *sync.RWMutex
	httpclient http.Client
	lb         *LoadBalancer
	httpregexp *regexp.Regexp
}

// NewProxy returns a new proxy instance.
// 新建并返回一个代理实例
func NewProxy(serviceName string, conf config.ProxyConfig,
	lbconf config.LoadBalancerConfig) *Proxy {
	var p Proxy
	p.name = serviceName
	// 服务必须有后端实例
	if lbconf.Hosts == nil || len(lbconf.Hosts) < 1 {
		fmt.Println("Missing backend instances for service " + serviceName)
		os.Exit(1)
	}
	p.lb = NewLoadBalancer(lbconf)
	p.port = conf.Port
	p.httpclient = http.Client{}
	p.bindhost = conf.BindHost
	if conf.BindHost == "" {
		p.bindhost = "localhost"
	}

	p.Protocol = conf.Protocol
	p.rules = map[MessageType][]Rule{Request: {}, Response: {}}
	p.ruleLock = new(sync.RWMutex)
	p.httpregexp = regexp.MustCompile("^https?://")
	return &p
}

// getRule returns first rule matched to the given request. If no stored rules match,
// a special NOPRule is returned.
// 返回首个匹配请求的规则, 不存在返回NOPRule
func (p *Proxy) getRule(r MessageType, reqID string, data []byte) Rule {
	p.ruleLock.RLock()
	defer p.ruleLock.RUnlock()
	// globallog.Debug("In getRule")
	for counter, rule := range p.rules[r] {
		globallog.WithField("ruleCounter", counter).Debug("Rule counter")
		//  If request ID is empty, do not match unless wildcard rule
		if reqID == "" {
			if rule.HeaderPattern == "*" || rule.BodyPattern == "*" {
				return rule
			}
			continue
		}

		// if requestID is a wildcard, pick up the first rule and return
		if reqID == "*" {
			return rule
		}

		if rule.HeaderPattern == "*" && rule.BodyPattern == "*" {
			return rule
		}

		if rule.HeaderPattern != "*" {
			b, err := regexp.Match(rule.HeaderPattern, []byte(reqID))
			if err != nil {
				globallog.WithFields(logrus.Fields{
					"reqID":         reqID,
					"errmsg":        err.Error(),
					"headerpattern": rule.HeaderPattern,
				}).Error("Rule request ID matching error")
				continue
			}
			if !b {
				globallog.Debug("Id regex no match")
				continue
			}
			//globallog.WithField("ruleCounter", rule.ToConfig()).Debug("Id regex match")
		}

		if data == nil {
			// No match if body pattern is empty, but match if rule pattern is empty or this is a special pattern
			if rule.BodyPattern != "*" {
				continue
			}
		} else {
			if rule.BodyPattern != "*" {
				globallog.WithField("ruleCounter", counter).Debug("Body pattern !*")
				b, err := regexp.Match(rule.BodyPattern, data)
				if err != nil {
					globallog.WithFields(logrus.Fields{
						"reqID":       reqID,
						"errmsg":      err.Error(),
						"bodypattern": rule.BodyPattern,
					}).Error("Rule body matching error")
					continue
				}
				if !b {
					globallog.Debug("Body regex no match")
					continue
				}
			}
		}
		//globallog.WithField("returning rule ", rule.ToConfig()).Debug("Id regex match")
		return rule
	}
	return NopRule
}

func glueHostAndPort(host string, port uint16) string {
	return host + ":" + strconv.Itoa(int(port))
}

// Run starts up a proxy in the desired mode: tcp or http. This is a blocking call
// 阻塞调用TCP或HTTP代理
func (p *Proxy) Run() {
	globallog.WithFields(logrus.Fields{
		"service":  p.name,
		"bindhost": p.bindhost,
		"port":     p.port,
		"protocol": p.Protocol}).Info("Starting up proxy")
	switch str.ToLower(p.Protocol) {
	case "tcp":
		localhost, err := net.ResolveTCPAddr("tcp", glueHostAndPort(p.bindhost, p.port))
		if err != nil {
			globallog.Error(err.Error())
			break
		}
		listener, err := net.ListenTCP("tcp", localhost)
		if err != nil {
			globallog.Error(err.Error())
			break
		}
		// Standard accept connection loop
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				globallog.Error(err.Error())
				continue
			}
			// go and handle the connection in separate thread
			go p.proxyTCP(conn)
		}
		break
	case "http":
		err := http.ListenAndServe(glueHostAndPort(p.bindhost, p.port), p)
		if err != nil {
			globallog.Error(err.Error())
		}
		break
	default:
		panic(p.Protocol + " not supported")
	}
}

func copyBytes(dest, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dest, src)
	dest.CloseWrite()
	src.CloseRead()
}

//TODO: Need to add connection termination in the middle of a connection & bandwidth throttling.
// Delay implementation is half-baked (only adds initial delay).
// 需要在连接和带宽限制的中间 添加连接终止。
// 延迟实现不完善（只会增加初始延迟）。

// proxyTCP is responsible for handling a new TCP connection.
// 代理TCP连接
func (p *Proxy) proxyTCP(conn *net.TCPConn) {

	//We can abort the connection immediately, in case of an Abort action.
	// 可以立即终止
	//FIXME: Need to have a way to abort in the middle of a connection too.
	rule := p.getRule(Request, "", nil)
	t := time.Now()

	// 随即决定执行延迟
	//FIXME: Add proper delay support for TCP channels.
	if (rule.DelayProbability > 0.0) &&
		drawAndDecide(rule.DelayDistribution, rule.DelayProbability) {
		proxylog.WithFields(logrus.Fields{
			"dest":     p.name,
			"source":   config.ProxyFor,
			"protocol": "tcp",
			"action":   "delay",
			"rule":     rule.ToConfig(),
			"testid":   p.getmyID(),
			"ts":       t.Format("2006-01-02T15:04:05.999999"),
		}).Info("Stream")
		time.Sleep(rule.DelayTime)
	}

	// 随即决定是否执行中断
	if (rule.AbortProbability > 0.0) &&
		drawAndDecide(rule.AbortDistribution, rule.AbortProbability) {
		proxylog.WithFields(logrus.Fields{
			"dest":     p.name,
			"source":   config.ProxyFor,
			"protocol": "tcp",
			"action":   "abort",
			"rule":     rule.ToConfig(),
			"testid":   p.getmyID(),
			"ts":       t.Format("2006-01-02T15:04:05.999999"),
		}).Info("Stream")
		conn.SetLinger(0)
		conn.Close()
		return
	}

	remotehost := p.lb.GetHost()
	rAddr, err := net.ResolveTCPAddr("tcp", remotehost)
	if err != nil {
		globallog.Error("Could not resolve remote address: " + err.Error())
		conn.Close()
		return
	}
	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		globallog.WithField("errmsg", err.Error()).Error("Could not connect to remote destination")
		conn.Close()
		return
	}
	// Make sure to copy data both directions, do it in separate threads
	// 确保双向复制数据，在单独的线程中执行
	var wg sync.WaitGroup
	wg.Add(2)
	//from proxier.go code in Kubernetes
	go copyBytes(conn, rConn, &wg)
	go copyBytes(rConn, conn, &wg)
	wg.Wait()
	conn.Close()
	rConn.Close()
}

//TODO: Need to add drip rule for HTTP (receiver taking in data byte by byte or sender sending data byte by byte, in low bandwidth situations).
// 需要为HTTP添加drip规则（在低带宽情况下，接收方逐字节接收数据或发送方逐字节发送数据）。
//TODO: In the request path, a slow receiver will cause buffer bloat at sender and ultimately lead to memory pressure -- VALIDATE
// 在请求路径中，接收速度慢会导致发送方缓冲区膨胀，并最终导致内存压力——验证
//TODO: In the response path, emulating a slow response will keep caller connection alive but ultimately delay full req processing, sending HTTP header first, then byte by byte
//	-- VALIDATE if this is useful for common frameworks in languages like Java, Python, Node, Ruby, etc.
// 在响应路径中，模拟慢速响应将使调用方连接保持活动状态，但最终会延迟完整的请求处理，首先发送HTTP头，然后逐字节发送
// --验证这对于Java、Python、Node、Ruby等语言中的通用框架是否有用。
///If its not true, there is no need to emulate drip at all.
// ServeHTTP: code that handles proxying of all HTTP requests
// 如果不是这样，就根本没有必要模仿滴水。

/* FIXME: BUG This method reads requests/replies into memory.
* DO NOT use this on very large size requests.
 */
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	//// 在请求开始前，对请求注入故障
	reqID := req.Header.Get(config.TrackingHeader)
	var rule Rule
	var decodedData []byte
	var cont bool
	data, err := readBody(req.Body)
	if reqID != "" {
		// Process the request, see if any rules match it.
		decodedData, err := decodeBody(data, req.Header.Get("content-type"),
			req.Header.Get("content-encoding"))
		if err != nil {
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":   reqID,
				"errmsg":  err.Error()}).Error("Error reading HTTP request")
			rule = NopRule
		} else {
			// Check if we were expecting it on the wire:
			//p.expectCheck(decodedData)

			// Get the rule
			rule = p.getRule(Request, reqID, decodedData)
		}
		cont := p.executeRequestRule(reqID, rule, req, decodedData, w)
		if !cont {
			return
		}
	}

	//// 代理执行请求
	// 负载平衡器
	var host = p.lb.GetHost()
	globallog.WithFields(logrus.Fields{
		"service": p.name,
		"reqID":   reqID,
		"host":    host}).Debug("Sending to")

	// If scheme (http/https is not explicitly specified, construct a http request to the requested service
	// 如果未指明是HTTP还是HTTPS，则加上http
	if !p.httpregexp.MatchString(host) {
		host = "http://" + host
	}
	newreq, err := http.NewRequest(req.Method, host+req.RequestURI, bytes.NewReader(data))
	if err != nil {
		status := http.StatusBadRequest
		http.Error(w, http.StatusText(status), status)
		globallog.WithFields(logrus.Fields{
			"service": p.name,
			"reqID":   reqID,
			"errmsg":  err.Error()}).Error("Could not construct proxy request")
		return
	}

	// Copy over the headers
	for k, v := range req.Header {
		if k != "Host" {
			for _, vv := range v {
				newreq.Header.Set(k, vv)
			}
		} else {
			newreq.Header.Set(k, host)
		}
	}

	// Make a connection
	starttime := time.Now()
	resp, err := p.httpclient.Do(newreq)
	respTime := time.Since(starttime)
	if err != nil {
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
		globallog.WithFields(
			logrus.Fields{
				"service":  p.name,
				"duration": respTime.String(),
				"status":   -1,
				"errmsg":   err.Error(),
			}).Info("Request proxying failed")
		return
	}

	//// 对回复注入故障
	// Read the response and see if it matches any rules
	rule = NopRule
	data, err = readBody(resp.Body)
	resp.Body.Close()
	if reqID != "" {
		decodedData, err = decodeBody(data, resp.Header.Get("content-type"),
			resp.Header.Get("content-encoding"))

		if err != nil {
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":   reqID,
				"errmsg":  err.Error()}).Error("Error reading HTTP reply")
			rule = NopRule
		} else {
			// Execute rules, if any
			rule = p.getRule(Response, reqID, decodedData)
		}

		cont = p.executeResponseRule(reqID, rule, resp, decodedData, respTime, w)
		if !cont {
			return
		}
	}

	//// 代理返回
	//return resp to caller
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Set(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(data)
	if err != nil {
		globallog.WithFields(logrus.Fields{
			"service": p.name,
			"errmsg":  err.Error()}).Error("HTTP Proxy write error")
	}
}

// Executes the rule on the request path or response path. ResponseWriter corresponds to the caller's connection
// Returns a bool, indicating whether we should continue request processing further or not
// 在请求路径或响应路径上执行规则。ResponseWriter对应于调用方的连接
// 返回bool，指示是否成功中止
func (p *Proxy) doHTTPAborts(reqID string, rule Rule, w http.ResponseWriter) bool {

	if rule.ErrorCode < 0 {
		hj, ok := w.(http.Hijacker)
		if !ok {
			// Revert to 500
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			globallog.WithFields(logrus.Fields{
				"service":     p.name,
				"reqID":       reqID,
				"abortmethod": "reset",
				"errmsg":      "Hijacking not supported",
			}).Error("Hijacking not supported")
			return false
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			// Revert to 500
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			globallog.WithFields(logrus.Fields{
				"service":     p.name,
				"reqID":       reqID,
				"abortmethod": "reset",
				"errmsg":      err.Error(),
			}).Error("Hijacking Failed")
			return false
		}

		// Close the connection, discarding any unacked data
		// 丢弃未应答数据并关闭
		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			tcpConn.SetLinger(0)
			tcpConn.Close()
		} else {
			//we couldn't type cast net.Conn to net.TCPConn successfully.
			//This shouldn't occur unless the underlying transport is not TCP. TODO 应该报错
			conn.Close()
		}
	} else {
		status := rule.ErrorCode
		http.Error(w, http.StatusText(status), status)
	}

	return true
}

// Fault injection happens here.
// Log every request with valid reqID irrespective of fault injection
// 此处发生故障注入。 不论是否有故障注入，使用有效的reqID记录每个请求。
// 返回是否终止
func (p *Proxy) executeRequestRule(reqID string, rule Rule, req *http.Request, body []byte, w http.ResponseWriter) bool {

	var actions []string
	delay, errorCode, retVal := time.Duration(0), -2, true
	t := time.Now()

	if rule.Enabled {
		// FIXME 概率总和等于1，必然触发其中一个?
		globallog.WithField("rule", rule.ToConfig()).Debug("execRequestRule")

		// 注入延迟
		if (rule.DelayProbability > 0.0) &&
			drawAndDecide(rule.DelayDistribution, rule.DelayProbability) {
			globallog.Printf("executeRequestRule delay")
			// In future, this could be dynamically computed -- variable delays
			delay = rule.DelayTime
			actions = append(actions, "delay")
			time.Sleep(rule.DelayTime)
		}

		// 注入中止
		if (rule.AbortProbability > 0.0) &&
			drawAndDecide(rule.AbortDistribution, rule.AbortProbability) &&
			p.doHTTPAborts(reqID, rule, w) {
			globallog.Printf("executeRequestRule abort")
			actions = append(actions, "abort")
			errorCode = rule.ErrorCode
			retVal = false
		}
	}

	proxylog.WithFields(logrus.Fields{
		"dest":           p.name,
		"source":         config.ProxyFor,
		"protocol":       "http",
		"trackingheader": config.TrackingHeader,
		"reqID":          reqID,
		"testid":         p.getmyID(),
		"actions":        "[" + str.Join(actions, ",") + "]",
		"delaytime":      delay.Nanoseconds() / (1000 * 1000), //actual time req was delayed in milliseconds
		"errorcode":      errorCode,                           //actual error injected or -2
		"uri":            req.RequestURI,
		"ts":             t.Format("2006-01-02T15:04:05.999999"),
		"rule":           rule.ToConfig(),
	}).Info("Request")

	return retVal
}

// Wrapper function around executeRule for the Response path
//TODO: decide if we want to log body and header
func (p *Proxy) executeResponseRule(reqID string, rule Rule, resp *http.Response, body []byte, after time.Duration, w http.ResponseWriter) bool {

	var actions []string
	delay, errorCode, retVal := time.Duration(0), -2, true
	t := time.Now()

	if rule.Enabled {
		// FIXME 概率总和等于1，必然触发其中一个?
		if (rule.DelayProbability > 0.0) &&
			drawAndDecide(rule.DelayDistribution, rule.DelayProbability) {
			globallog.Printf("executeResponseRule delay")
			// In future, this could be dynamically computed -- variable delays
			delay = rule.DelayTime
			actions = append(actions, "delay")
			time.Sleep(rule.DelayTime)
		}

		if (rule.AbortProbability > 0.0) &&
			drawAndDecide(rule.AbortDistribution, rule.AbortProbability) &&
			p.doHTTPAborts(reqID, rule, w) {
			globallog.Printf("executeResponseRule abort")
			actions = append(actions, "abort")
			errorCode = rule.ErrorCode
			retVal = false
		}
	}

	proxylog.WithFields(logrus.Fields{
		"dest":           p.name,
		"source":         config.ProxyFor,
		"protocol":       "http",
		"trackingheader": config.TrackingHeader,
		"reqID":          reqID,
		"testid":         p.getmyID(),
		"actions":        "[" + str.Join(actions, ",") + "]",
		"delaytime":      delay.Nanoseconds() / (1000 * 1000), //actual time resp was delayed in milliseconds
		"errorcode":      errorCode,                           //actual error injected or -2
		"status":         resp.StatusCode,
		"duration":       after.String(),
		"ts":             t.Format("2006-01-02T15:04:05.999999"),
		//log header/body?
		"rule": rule.ToConfig(),
	}).Info("Response")

	return retVal
}

// AddRule adds a new rule to the proxy. All requests/replies carrying the trackingheader will be checked
// against all rules, if something matches, the first matched rule will be executed
func (p *Proxy) AddRule(r Rule) {
	//TODO: check validity of regexes before installing a rule!
	p.ruleLock.Lock()
	p.rules[r.MType] = append(p.rules[r.MType], r)
	p.ruleLock.Unlock()
}

// RemoveRule removes a rule from this proxy
func (p *Proxy) RemoveRule(r Rule) bool {
	p.ruleLock.RLock()
	n := len(p.rules[r.MType])
	b := p.rules[r.MType][:0]
	for _, x := range p.rules[r.MType] {
		if x != r {
			b = append(b, x)
		}
	}
	p.ruleLock.RUnlock()
	// FIXME 并发Bug: 同时删除多个操作，部分删除会被覆盖
	p.ruleLock.Lock()
	p.rules[r.MType] = b
	p.ruleLock.Unlock()
	return len(p.rules[r.MType]) != n
}

// GetRules returns all rules currently active at this proxy
func (p *Proxy) GetRules() []Rule {
	globallog.Debug("REST get rules")
	p.ruleLock.RLock()
	defer p.ruleLock.RUnlock()
	return append(p.rules[Request], p.rules[Response]...)
}

// GetInstances returns the service instances available in the loadbalancer for a given service
func (p *Proxy) GetInstances() []string {
	return p.lb.GetInstances()
}

// SetInstances sets the service instances available in the loadbalancer for a given service
func (p *Proxy) SetInstances(hosts []string) {
	p.lb.SetInstances(hosts)
}

// Reset clears proxy state. Removes all stored rules and expects. However loadbalancer hosts remain.
func (p *Proxy) Reset() {
	// lock rules, clear, unlock
	p.ruleLock.Lock()
	p.rules = map[MessageType][]Rule{Request: {},
		Response: {}}
	p.ruleLock.Unlock()
}

func (p *Proxy) SetTestID(testID string) {
	p.testid = testID
	t := time.Now()
	proxylog.WithFields(logrus.Fields{
		"source": config.ProxyFor,
		"dest":   p.name,
		"testid": testID,
		"ts":     t.Format("2006-01-02T15:04:05.999999"),
	}).Info("Test start")
}

func (p *Proxy) getmyID() string {
	return p.testid
}

func (p *Proxy) StopTest(testID string) bool {
	t := time.Now()
	if testID == p.testid {
		p.testid = ""
		return true
	}
	proxylog.WithFields(logrus.Fields{
		"source": config.ProxyFor,
		"dest":   p.name,
		"ts":     t.Format("2006-01-02T15:04:05.999999"),
		"testid": testID,
	}).Info("Test stop")
	return false
}

// readBody is shortcut method to get all bytes from a reader
func readBody(r io.Reader) ([]byte, error) {
	result, err := ioutil.ReadAll(r)
	return result, err
}

// Take the raw bytes from a request (or response) and run them through a decompression
// algorithm so we can run the regex on it or log it.
// 对于gzip和deflate压缩的原始数据解压，其它不变，来正则匹配或记录
func decodeBody(raw []byte, ct string, ce string) ([]byte, error) {
	if str.Contains(ce, "gzip") {
		gr, err := gzip.NewReader(bytes.NewBuffer(raw))
		if err != nil {
			return []byte{}, err
		}
		result, err := ioutil.ReadAll(gr)
		return result, err
	} else if str.Contains(ce, "deflate") {
		zr, err := zlib.NewReader(bytes.NewBuffer(raw))
		if err != nil {
			return []byte{}, err
		}
		result, err := ioutil.ReadAll(zr)
		return result, err
	}
	return raw, nil
}

// drawAndDecide draws from a given distribution and compares (<) the result to a threshold.
// This determines whether an action should be taken or not
// 根据随机数的分布和概率进行随机，决定是否执行
func drawAndDecide(distribution ProbabilityDistribution, probability float64) bool {
	//	fmt.Printf("In draw and decide with dis %s, thresh %f", DistributionString(distribution), probability);

	switch distribution {
	case ProbUniform:
		return rand.Float64() < probability
	case ProbExponential:
		return rand.ExpFloat64() < probability
	case ProbNormal:
		return rand.NormFloat64() < probability
	default:
		globallog.Warnf("Unknown probability distribution %d, defaulting to coin flip", distribution)
		return rand.Float64() < .5
	}
}
