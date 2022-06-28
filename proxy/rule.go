package proxy

import (
	"errors"
	"github.com/YuSitong1999/gremlinproxy/config"
	str "strings"
	"time"
)

// MessageType is just that a type: request or reply
type MessageType uint

// ProbabilityDistribution is a type for probability distribution functions for rules
type ProbabilityDistribution uint

// 概率分布
const (
	ProbUniform = iota
	ProbExponential
	ProbNormal
)

// 概率分布 -> 名字
var distributionMap = map[ProbabilityDistribution]string{
	ProbUniform:     "uniform",
	ProbExponential: "exponential",
	ProbNormal:      "normal",
}

//消息类型 message channel type between client and server, via the proxy
const (
	MTypeUnknown MessageType = iota
	Request
	Response
	Publish
	Subscribe
)

//消息类型 -> 名字
var rMap = map[MessageType]string{
	MTypeUnknown: "unknown",
	Request:      "request",
	Response:     "response",
	Publish:      "publish",
	Subscribe:    "subscribe",
}

// Rule is a universal type for all rules.
type Rule struct {
	Source string
	Dest   string
	MType  MessageType

	//Select only messages that match pattens specified in these fields
	BodyPattern   string
	HeaderPattern string

	// Probability float64
	// Distribution string

	// First delay, then mangle and then abort
	// One could set the probabilities of these variables to 0/1 to toggle them on or off
	// We effectively get 8 combinations but only few make sense.
	DelayProbability   float64
	DelayDistribution  ProbabilityDistribution
	MangleProbability  float64
	MangleDistribution ProbabilityDistribution
	AbortProbability   float64
	AbortDistribution  ProbabilityDistribution

	//TestID       string
	DelayTime     time.Duration
	ErrorCode     int
	SearchString  string
	ReplaceString string
	Enabled       bool
}

// NopRule is a rule that does nothing. Useful default return value
var NopRule = Rule{Enabled: false}

// 分布名字 -> 编号
func getDistribution(distribution string) (ProbabilityDistribution, error) {

	if distribution == "" {
		return ProbUniform, nil
	}

	switch str.ToLower(distribution) {
	case "uniform":
		return ProbUniform, nil
	case "exponential":
		return ProbExponential, nil
	case "normal":
		return ProbNormal, nil
	default:
		return ProbUniform, errors.New("Unknown probability distribution")
	}
}

// NewRule return a new rule based on the config.
func NewRule(c config.RuleConfig) (Rule, error) {
	var r Rule
	var err error
	// Convert request/reply types
	switch str.ToLower(c.MType) {
	case "request":
		r.MType = Request
	case "response":
		r.MType = Response
	case "publish":
		r.MType = Publish
	case "subscribe":
		r.MType = Subscribe
	default:
		return NopRule, errors.New("Unsupported request type")
	}
	r.BodyPattern = c.BodyPattern
	r.HeaderPattern = c.HeaderPattern
	//sanity check
	//at least header or body pattern must be non-empty
	if r.HeaderPattern == "" {
		return NopRule, errors.New("HeaderPattern cannot be empty (specify * instead)")
	}

	if r.BodyPattern == "" {
		r.BodyPattern = "*"
	}

	r.DelayDistribution, err = getDistribution(c.DelayDistribution)
	if err != nil {
		return NopRule, err
	}
	r.MangleDistribution, err = getDistribution(c.MangleDistribution)
	if err != nil {
		return NopRule, err
	}

	r.AbortDistribution, err = getDistribution(c.AbortDistribution)
	if err != nil {
		return NopRule, err
	}

	r.DelayProbability = c.DelayProbability
	r.MangleProbability = c.MangleProbability
	r.AbortProbability = c.AbortProbability
	// 至少有一种故障
	valid := ((r.DelayProbability > 0.0) || (r.MangleProbability > 0.0) || (r.AbortProbability > 0.0))
	if !valid {
		return NopRule, errors.New("Atleast one of delayprobability, mangleprobability, abortprobability must be non-zero and <=1.0")
	}

	// 大于1的概率实际上视为1，必然发生

	if c.DelayTime != "" {
		var err error
		r.DelayTime, err = time.ParseDuration(c.DelayTime)
		if err != nil {
			globallog.WithField("errmsg", err.Error()).Warn("Could not parse rule delay time")
			return NopRule, err
		}
	} else {
		r.DelayTime = time.Duration(0)
	}

	r.ErrorCode = c.ErrorCode
	r.SearchString = c.SearchString
	r.ReplaceString = c.ReplaceString
	r.Source = c.Source
	r.Dest = c.Dest
	r.Enabled = true
	return r, nil
}

// ToConfig 输出规则的可读版本 converts the rule into a human-readable string config.
func (r *Rule) ToConfig() config.RuleConfig {
	var c config.RuleConfig

	c.Source = r.Source
	c.Dest = r.Dest
	c.MType = rMap[r.MType]

	c.HeaderPattern = r.HeaderPattern
	c.BodyPattern = r.BodyPattern

	c.DelayDistribution = distributionMap[r.DelayDistribution]
	c.MangleDistribution = distributionMap[r.MangleDistribution]
	c.AbortDistribution = distributionMap[r.AbortDistribution]

	c.DelayProbability = r.DelayProbability
	c.MangleProbability = r.MangleProbability
	c.AbortProbability = r.AbortProbability

	c.DelayTime = r.DelayTime.String()
	c.ErrorCode = r.ErrorCode
	c.SearchString = r.SearchString
	c.ReplaceString = r.ReplaceString

	return c
}
