package router

import (
	// "bufio"
	// "bytes"
	"encoding/json"
	"errors"
	"github.com/YuSitong1999/gremlinproxy/config"
	"github.com/YuSitong1999/gremlinproxy/proxy"
	"github.com/YuSitong1999/gremlinproxy/services"
	// "io"
	"net/http"
	// "os"
	"strconv"
	str "strings"
	// "sync"
	"github.com/julienschmidt/httprouter"
)

var logstashHost string
var log = config.GlobalLogger

// Router maintains all the state. It keeps a list or remote services we talk
// to, and exposes a REST
// API for configuring router rules
// 维护所有状态：所有远程服务 和 路由规则配置接口
type Router struct {
	services []*services.Service
	RESTPort uint16
	// map names of remote services to objects
	serviceNameMap map[string]*services.Service
}

// NewRouter creates a new router and configures underlying services
// 创建路由 和 配置下层服务
func NewRouter(conf config.Config) Router {
	var r Router
	r.services = make([]*services.Service, len(conf.Services))
	r.serviceNameMap = make(map[string]*services.Service)
	for i, sconf := range conf.Services {
		s := services.NewService(sconf)
		r.services[i] = s
		r.serviceNameMap[s.Name] = s
	}
	r.RESTPort = conf.Router.Port
	logstashHost = conf.LogstashHost
	config.ProxyFor = conf.Router.Name // TODO ?
	return r
}

// Run starts up the control loop of the router.  listening for any REST messages
func (r *Router) Run() {
	for _, service := range r.services {
		go service.Proxy.Run()
	}
	log.Info("Router initialized")
	// blocking call here
	r.exposeREST()
}

// 暴露REST配置接口
func (r *Router) exposeREST() {
	// Expose a REST configuration interface
	hr := httprouter.New()
	hr.GET("/gremlin/v1", restHello)
	// 对规则：新增、删除、显示、重置
	hr.POST("/gremlin/v1/rules/add", r.AddRule)
	hr.POST("/gremlin/v1/rules/remove", r.RemoveRule)
	hr.GET("/gremlin/v1/rules/list", r.ListRules)
	hr.DELETE("/gremlin/v1/rules", r.Reset)
	// 对实例：获取、设置、移除
	hr.GET("/gremlin/v1/proxy/:service/instances", r.GetInstances)
	hr.PUT("/gremlin/v1/proxy/:service/:instances", r.SetInstances)
	hr.DELETE("/gremlin/v1/proxy/:service/instances", r.RemoveInstances)
	// 对测试：设置、移除
	hr.PUT("/gremlin/v1/test/:id", r.SetTest)
	hr.DELETE("/gremlin/v1/test/:id", r.RemoveTest)
	// 运行
	log.WithField("port", r.RESTPort).Debug("Running REST server")
	http.ListenAndServe(":"+strconv.Itoa(int(r.RESTPort)), hr)
}

// AddRule adds a rule to the list of active rules
func (r *Router) AddRule(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s, rule, err := r.readRule(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	// Put the rule into the proxy that belongs to the correct service
	s.Proxy.AddRule(*rule)
	// Everything went well
	w.Write([]byte(config.OK))
	log.Debug("Added rule")
}

// ListRules returns a list of rules at all proxies in JSON format
func (r *Router) ListRules(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var readableRules []config.RuleConfig
	for _, s := range r.services {
		for _, rule := range s.Proxy.GetRules() {
			// Convert to human-readable
			c := rule.ToConfig()
			readableRules = append(readableRules, c)
		}
	}
	log.WithField("rules", readableRules).Debug("List rules:")
	// Write it out
	e := json.NewEncoder(w)
	if e.Encode(readableRules) != nil {
		log.Error("Error encoding router rules to JSON")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Encoding rules problem"))
	}
}

// RemoveRule removes the rule from the list of active rules
// FIXME: Currently this relies on internal Go equal semantics. Not ideal, but works for now
func (r *Router) RemoveRule(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s, rule, err := r.readRule(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	res := s.Proxy.RemoveRule(*rule)
	// Everything went well
	w.Write([]byte(config.OK + "\n" + strconv.FormatBool(res)))
	log.Debug("Removed rule")
}

// Reset clears router state. This means all active proxies and their rules get cleared.
func (r *Router) Reset(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	for _, s := range r.services {
		s.Proxy.Reset()
	}
	w.Write([]byte(config.OK))
}

// restHello is just a demo REST API function
func restHello(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	w.Write([]byte("Hello, I am " + config.NAME))
}

// Overwrite the load balancer pool for a given service name
func (r *Router) SetInstances(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	serviceName := params.ByName("service")
	hostlist := params.ByName("hosts")
	log.Debug("name=" + serviceName + ", hosts=" + hostlist)
	s, exists := r.serviceNameMap[serviceName]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such service " + serviceName))
		return
	}
	if hostlist == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Empty host list for " + serviceName))
		return
	}
	hosts := str.Split(hostlist, ",")
	s.Proxy.SetInstances(hosts)
	w.Write([]byte(config.OK))
}

func (r *Router) GetInstances(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	serviceName := params.ByName("service")
	s, exists := r.serviceNameMap[serviceName]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such service " + serviceName))
		return
	}

	hosts := s.Proxy.GetInstances()
	hostlist := str.Join(hosts, ",")
	w.Write([]byte(config.OK))
	w.Write([]byte(hostlist))
}

func (r *Router) RemoveInstances(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	serviceName := params.ByName("service")
	s, exists := r.serviceNameMap[serviceName]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such service " + serviceName))
		return
	}

	s.Proxy.SetInstances(make([]string, 0))
	w.Write([]byte(config.OK))
}

// readRule converts JSON rule POSTed to us to a Rule object
func (r *Router) readRule(req *http.Request) (*services.Service, *proxy.Rule, error) {
	d := json.NewDecoder(req.Body)

	// Try to automatically decode this from JSON into a config
	var ruleconf config.RuleConfig
	err := d.Decode(&ruleconf)
	if err != nil {
		log.Warning("Could not read JSON request\n" + err.Error())
		return nil, nil, err
	}

	//check if source matches the router name
	if ruleconf.Source != config.ProxyFor {
		log.WithField("Source", ruleconf.Source).Warning("Rule not targeted for this Router")
		return nil, nil, errors.New("Router name does not match Source " + ruleconf.Source)
	}

	// Check if we have the desired service for which this rule applies.
	s, exists := r.serviceNameMap[ruleconf.Dest]
	if !exists {
		log.WithField("Dest", ruleconf.Dest).Warning("Service specified in rule not found")
		return nil, nil, errors.New("Dest service " + ruleconf.Dest + " not known")
	}

	//sanity checks in rule.go
	// Create a new rule
	rule, err := proxy.NewRule(ruleconf)
	if err != nil {
		log.WithField("errmsg", err.Error()).Info("Badly formed rule ignored")
		return nil, nil, err
	}
	return s, &rule, nil
}

// SetTest tells the router that a test with given ID will be happening
func (r *Router) SetTest(w http.ResponseWriter, req *http.Request,
	params httprouter.Params) {
	testid := params.ByName("id")
	for _, s := range r.services {
		s.Proxy.SetTestID(testid)
	}
	w.Write([]byte(config.OK))
}

func (r *Router) RemoveTest(w http.ResponseWriter, req *http.Request,
	params httprouter.Params) {
	testid := params.ByName("id")
	for _, s := range r.services {
		s.Proxy.StopTest(testid)
	}
	w.Write([]byte(config.OK))
}
