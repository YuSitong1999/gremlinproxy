package services

import (
	"github.com/YuSitong1999/gremlinproxy/config"
	"github.com/YuSitong1999/gremlinproxy/proxy"
)

// Service is an encapsulation of a remote endpoint. It contains the proxy
// instance doing the forwarding.
// It could potentially be augmented to encapsulate functionality for discovering service
// instances through zookeper (or potentially other services)
// 服务是远程端点的封装。它包含执行转发的代理实例。
// 可以对其进行扩展，以封装通过zookeper（或潜在的其他服务）发现服务实例的功能
type Service struct {
	Name  string
	Proxy *proxy.Proxy
}

// NewService returns a new service given the config
func NewService(conf config.ServiceConfig) *Service {
	var s = Service{
		Name:  conf.Name,
		Proxy: proxy.NewProxy(conf.Name, conf.Proxyconf, conf.LBConfig),
	}
	return &s
}

// GetInstances gets the service instances for a given service
func (s *Service) GetInstances() []string {
	return s.Proxy.GetInstances()
}

// SetInstances sets the service instances for a given service
func (s *Service) SetInstances(hosts []string) {
	s.Proxy.SetInstances(hosts)
}
