package challenge

import (
	http_cel "codeberg.org/gone/http-cel"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
	"github.com/google/cel-go/cel"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

type Register map[Id]*Registration

func (r Register) Get(id Id) (*Registration, bool) {
	c, ok := r[id]
	return c, ok
}

func (r Register) GetByName(name string) (*Registration, Id, bool) {
	for id, c := range r {
		if c.Name == name {
			return c, id, true
		}
	}

	return nil, 0, false
}

var idCounter Id

// DefaultDuration TODO: adjust
const DefaultDuration = time.Hour * 24 * 7

var DefaultKeyHeaders = []string{
	"Accept-Language",
	// General browser information
	"User-Agent",
}

func (r Register) Create(state StateInterface, name string, pol policy.Challenge, replacer *strings.Replacer) (*Registration, Id, error) {
	runtime, ok := Runtimes[pol.Runtime]
	if !ok {
		return nil, 0, fmt.Errorf("unknown challenge runtime %s", pol.Runtime)
	}

	reg := &Registration{
		Name:       name,
		Path:       path.Join(state.UrlPath(), "challenge", name),
		Duration:   pol.Duration,
		KeyHeaders: DefaultKeyHeaders,
	}

	if reg.Duration == 0 {
		reg.Duration = DefaultDuration
	}

	// allow nesting
	var conditions []string
	for _, cond := range pol.Conditions {
		if replacer != nil {
			cond = replacer.Replace(cond)
		}
		conditions = append(conditions, cond)
	}

	if len(conditions) > 0 {
		var err error
		reg.Condition, err = state.RegisterCondition(http_cel.OperatorOr, conditions...)
		if err != nil {
			return nil, 0, fmt.Errorf("error compiling condition: %w", err)
		}
	}

	if _, oldId, ok := r.GetByName(reg.Name); ok {
		reg.id = oldId
	} else {
		idCounter++
		reg.id = idCounter
	}

	err := runtime(state, reg, pol.Parameters)
	if err != nil {
		return nil, 0, fmt.Errorf("error filling registration: %v", err)
	}
	r[reg.id] = reg
	return reg, reg.id, nil
}

func (r Register) Add(c *Registration) Id {
	if _, oldId, ok := r.GetByName(c.Name); ok {
		c.id = oldId
		r[oldId] = c
		return oldId
	} else {
		idCounter++
		c.id = idCounter
		r[idCounter] = c
		return idCounter
	}
}

type Registration struct {
	// id The assigned internal identifier
	id Id

	// Name The unique name for this challenge
	Name string

	// Class whether this challenge is transparent or otherwise
	Class Class

	// Condition A CEL condition which is passed the same environment as general rules.
	// If nil, always true
	// If non-nil, must return true for this challenge to be allowed to be executed
	Condition cel.Program

	// Path The url path that this challenge is hosted under for the Handler to be called.
	Path string

	// Duration How long this challenge will be valid when passed
	Duration time.Duration

	// Handler An HTTP handler for all requests coming on the Path
	// This handler will need to handle MakeChallengeUrlSuffix and VerifyChallengeUrlSuffix as well if needed
	// Recommended to use http.ServeMux
	Handler http.Handler

	// Verify Verify an issued token
	Verify            VerifyFunc
	VerifyProbability float64

	// KeyHeaders The client headers used in key generation, in this order
	KeyHeaders []string

	// IssueChallenge Issues a challenge to a request.
	// If Class is ClassTransparent and VerifyResult is !VerifyResult.Ok(), continue with other challenges
	// TODO: have this return error as well
	IssueChallenge func(w http.ResponseWriter, r *http.Request, key Key, expiry time.Time) VerifyResult

	// Object used to handle state or similar
	// Can be nil if no state is needed
	// If non-nil must implement io.Closer even if there's nothing to do
	Object io.Closer
}

type VerifyFunc func(key Key, token []byte, r *http.Request) (VerifyResult, error)

func (reg Registration) Id() Id {
	return reg.id
}

type FillRegistration func(state StateInterface, reg *Registration, parameters ast.Node) error

var Runtimes = make(map[string]FillRegistration)
