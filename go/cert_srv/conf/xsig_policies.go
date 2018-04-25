// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/trc"
)

const (
	XSigPolicyDir    = "xsig"
	FieldString      = "field"
	KeyString        = "key" // Might be preferrable to use "key/index"
	LowerBoundString = "atLeast"
	UpperBoundString = "atMost"
)

type XSigPolicies struct {
	// Map that maps ISDs to policies checking functions
	poliMap map[addr.ISD](func(t *trc.TRC) bool)
}

// This is modeled after go/lib/crypto/trc/trc.go and defines what type of
// constraints can be expressed in a policy.
type policy struct {
	allowQuarantine        bool
	minTimeSinceCreation   uint64
	maxTimeSinceCreation   uint64
	minTimeUntilExpiration uint64
	maxTimeUntilExpiration uint64
	minGracePeriod         uint64
	maxGracePeriod         uint64
	minQuorumCAs           uint32
	maxQuorumCAs           uint32
	minQuorumTRC           uint32
	maxQuorumTRC           uint32
	minThresholdEEPKI      uint32
	maxThresholdEEPKI      uint32
	descriptionWhitelist   []string
	onlineKeyAlgWhitelist  []string
	offlineKeyAlgWhitelist []string
}

// Attempts to create checking functions from the policies in the designated
// directory. The policies are specified in JSON.
func (c *Conf) loadXSigPolicies() (*XSigPolicies, error) {
	// Loop over all correctly named files
	policies := &XSigPolicies{}
	files, err := filepath.Glob(fmt.Sprintf("%s/ISD*.policy", filepath.Join(c.ConfDir, XSigPolicyDir)))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		re := regexp.MustCompile(`ISD(\d+).policy$`)
		s := re.FindStringSubmatch(file)
		isd, err := addr.ISDFromString(s[0])
		if err != nil {
			log.Error("Couldn't read cross-signing policy file name", "err", err)
			continue
		}
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			log.Error("Couldn't read cross-signing policy file", "err", err)
			continue
		}
		p := &policy{}
		if err := json.Unmarshal(raw, p); err != nil {
			log.Error("Couldn't unmarshal cross-signing policy", "err", err)
		}
		descriptionWLMap := listToMap(p.descriptionWhitelist)
		onlineAlgWLMap := listToMap(p.onlineKeyAlgWhitelist)
		offlineAlgWLMap := listToMap(p.offlineKeyAlgWhitelist)
		checkFunction := func(t *trc.TRC) bool {
			if !p.allowQuarantine && t.Quarantine {
				return false
			}
			// Check ranges of all numerical constraints in the policy
			currTime := uint64(time.Now().Unix())
			timeSinceCreation := currTime - t.CreationTime
			if !inRange(timeSinceCreation,
				p.minTimeSinceCreation, p.maxTimeSinceCreation) {
				return false
			}
			timeUntilExpiration := t.ExpirationTime - currTime
			if !inRange(timeUntilExpiration,
				p.minTimeUntilExpiration, p.maxTimeUntilExpiration) {
				return false
			}
			if !inRange(t.GracePeriod, p.minGracePeriod, p.maxGracePeriod) {
				return false
			}
			if !inRange(t.QuorumCAs, p.minQuorumCAs, p.maxQuorumCAs) {
				return false
			}
			if !inRange(t.QuorumTRC, p.minQuorumTRC, p.maxQuorumTRC) {
				return false
			}
			if !inRange(t.ThresholdEEPKI, p.minThresholdEEPKI, p.maxThresholdEEPKI) {
				return false
			}

			// Check occurrence of non-whitelisted string attributes
			if _, ok := descriptionWLMap[t.Description]; !ok {
				return false
			}
			onlineKeyAlgs, offlineKeyAlgs := getAlgorithms(t)
			for _, algo := range onlineKeyAlgs {
				if _, ok := onlineAlgWLMap[algo]; !ok {
					return false
				}
			}
			for _, algo := range offlineKeyAlgs {
				if _, ok := offlineAlgWLMap[algo]; !ok {
					return false
				}
			}
			// No check failed
			return true
		}
		policies.poliMap[isd] = checkFunction
	}
	return policies, nil
}

func (p *XSigPolicies) check(t *trc.TRC) bool {
	checkFunction, ok := p.poliMap[t.ISD]
	if !ok {
		return false
	}
	return checkFunction(t)
}

func listToMap(keys []string) (resMap map[string]struct{}) {
	for _, key := range keys {
		resMap[key] = struct{}{}
	}
	return resMap
}

func getAlgorithms(t *trc.TRC) (onlineAlgs, offlineAlgs []string) {
	for _, c := range t.CoreASes {
		onlineAlgs = append(onlineAlgs, c.OnlineKeyAlg)
		offlineAlgs = append(offlineAlgs, c.OfflineKeyAlg)
	}
	onlineAlgs = append(onlineAlgs, t.RAINS.OnlineKeyAlg)
	for _, r := range t.RootCAs {
		onlineAlgs = append(onlineAlgs, r.OnlineKeyAlg)
	}
	return onlineAlgs, offlineAlgs
}

func inRange(x, lower, upper interface{}) bool { // TODO check if there is an interface for "<"
	switch valX := x.(type) {
	case uint32:
		valLower := lower.(uint32)
		valUpper := upper.(uint32)
		return valX < valLower || valX > valUpper
	case uint64:
		valLower := lower.(uint64)
		valUpper := upper.(uint64)
		return valX < valLower || valX > valUpper
	default:
		return false
	}
}
