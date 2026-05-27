package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/chaos"
)

type profileSpec struct {
	Name string
	Prof chaos.Profile
}

var profiles = map[string]profileSpec{
	"A-lowlat-5M": {
		Name: "A-lowlat-5M",
		Prof: chaos.Profile{Bandwidth: 5_000_000, Delay: 5 * time.Millisecond, Jitter: time.Millisecond},
	},
	"B-bulk-50M": {
		Name: "B-bulk-50M",
		Prof: chaos.Profile{Bandwidth: 50_000_000, Delay: 80 * time.Millisecond, Jitter: 10 * time.Millisecond},
	},
	"C-bulk-50M": {
		Name: "C-bulk-50M",
		Prof: chaos.Profile{Bandwidth: 50_000_000, Delay: 90 * time.Millisecond, Jitter: 10 * time.Millisecond},
	},
	"B-evening": {
		Name: "B-evening",
		Prof: chaos.Profile{Bandwidth: 12_000_000, Delay: 140 * time.Millisecond, Jitter: 30 * time.Millisecond, LossPct: 0.5},
	},
	"C-evening": {
		Name: "C-evening",
		Prof: chaos.Profile{Bandwidth: 25_000_000, Delay: 120 * time.Millisecond, Jitter: 25 * time.Millisecond, LossPct: 0.2},
	},
	"bad-candidate": {
		Name: "bad-candidate",
		Prof: chaos.Profile{Bandwidth: 50_000_000, Delay: 200 * time.Millisecond, Jitter: 80 * time.Millisecond, LossPct: 3.0},
	},
}

type config struct {
	cases          []string
	estimators     []string
	profiles       []profileSpec
	repeats        int
	passiveRates   []int64
	passiveDur     time.Duration
	boundedBytes   int64
	adaptiveMin    int64
	adaptiveMax    int64
	adaptiveEps    float64
	calibrateBytes int64
	trickleDur     time.Duration
	trickleBurst   int64
	trickleEvery   time.Duration
	timeout        time.Duration
	jsonl          bool
}

type result struct {
	Case           string  `json:"case"`
	Estimator      string  `json:"estimator"`
	Profile        string  `json:"profile"`
	Repeat         int     `json:"repeat"`
	AppRateBPS     int64   `json:"app_rate_bps,omitempty"`
	GroundTruthBPS int64   `json:"ground_truth_bps"`
	EstimateBPS    float64 `json:"estimate_bps"`
	Confidence     float64 `json:"confidence"`
	ErrorPct       float64 `json:"error_pct"`
	ElapsedMS      int64   `json:"elapsed_ms"`
	AppBytes       int64   `json:"app_bytes"`
	ProbeBytes     int64   `json:"probe_bytes"`
	SelectedTarget string  `json:"selected_target,omitempty"`
	Promoted       bool    `json:"promoted,omitempty"`
	FalsePromotion bool    `json:"false_promotion,omitempty"`
	FalseDemotion  bool    `json:"false_demotion,omitempty"`
	FlapCount      int     `json:"flap_count,omitempty"`
	UserCPUMS      int64   `json:"user_cpu_ms,omitempty"`
	SysCPUMS       int64   `json:"sys_cpu_ms,omitempty"`
	CPUPct         float64 `json:"cpu_pct,omitempty"`
	Notes          string  `json:"notes,omitempty"`
	Error          string  `json:"error,omitempty"`
}

type sample struct {
	bytes   int64
	elapsed time.Duration
}

func main() {
	var (
		cases           = flag.String("case", "cp1,cp2", "comma-separated cases: cp1,cp2,cp3,cp4,cp5,cp6,cp7,all")
		estimators      = flag.String("estimators", "passive,bounded,adaptive,trickle,calibration", "comma-separated estimators")
		profileNames    = flag.String("profiles", "A-lowlat-5M,B-bulk-50M,C-bulk-50M,B-evening,C-evening,bad-candidate", "comma-separated profile names")
		repeats         = flag.Int("repeats", 1, "repeats per case/profile/estimator")
		passiveRates    = flag.String("passive-rates", "1000000,5000000,0", "CP2 app rates in bit/s; 0 means unbounded")
		passiveDur      = flag.Duration("passive-duration", 5*time.Second, "CP2 duration for paced passive samples")
		boundedKiB      = flag.Int64("bounded-kib", 1024, "bounded probe bytes in KiB")
		adaptiveMinKiB  = flag.Int64("adaptive-min-kib", 256, "adaptive probe starting size in KiB")
		adaptiveMaxMiB  = flag.Int64("adaptive-max-mib", 8, "adaptive probe maximum size in MiB")
		adaptiveEpsPct  = flag.Float64("adaptive-epsilon-pct", 20, "adaptive stop threshold between probe rounds")
		calibrateMiB    = flag.Int64("calibration-mib", 16, "calibration bytes in MiB")
		trickleDur      = flag.Duration("trickle-duration", 5*time.Second, "total trickle estimator duration")
		trickleBurstKiB = flag.Int64("trickle-burst-kib", 256, "bytes per trickle sample in KiB")
		trickleEvery    = flag.Duration("trickle-every", 750*time.Millisecond, "delay between trickle samples")
		timeout         = flag.Duration("timeout", 2*time.Minute, "timeout per profile")
		jsonl           = flag.Bool("jsonl", true, "print one JSON object per run")
	)
	flag.Parse()

	cfg, err := buildConfig(config{
		cases:          splitCSV(*cases),
		estimators:     splitCSV(*estimators),
		repeats:        *repeats,
		passiveDur:     *passiveDur,
		boundedBytes:   *boundedKiB << 10,
		adaptiveMin:    *adaptiveMinKiB << 10,
		adaptiveMax:    *adaptiveMaxMiB << 20,
		adaptiveEps:    *adaptiveEpsPct / 100,
		calibrateBytes: *calibrateMiB << 20,
		trickleDur:     *trickleDur,
		trickleBurst:   *trickleBurstKiB << 10,
		trickleEvery:   *trickleEvery,
		timeout:        *timeout,
		jsonl:          *jsonl,
	}, *profileNames, *passiveRates)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx := context.Background()
	results := runAll(ctx, cfg)
	if !cfg.jsonl {
		for _, r := range results {
			_ = json.NewEncoder(os.Stdout).Encode(r)
		}
	}
	printSummary(results)
	for _, r := range results {
		if r.Error != "" {
			os.Exit(1)
		}
	}
}

func buildConfig(cfg config, profileCSV, rateCSV string) (config, error) {
	if len(cfg.cases) == 0 {
		return cfg, fmt.Errorf("need at least one case")
	}
	var cases []string
	for _, c := range cfg.cases {
		switch c {
		case "all":
			cases = append(cases, "cp1", "cp2", "cp3", "cp4", "cp5", "cp6", "cp7")
		case "cp1", "cp2", "cp3", "cp4", "cp5", "cp6", "cp7":
			cases = append(cases, c)
		default:
			return cfg, fmt.Errorf("unknown case %q", c)
		}
	}
	cfg.cases = unique(cases)

	if len(cfg.estimators) == 0 {
		return cfg, fmt.Errorf("need at least one estimator")
	}
	for _, e := range cfg.estimators {
		switch e {
		case "passive", "bounded", "adaptive", "trickle", "calibration":
		default:
			return cfg, fmt.Errorf("unknown estimator %q", e)
		}
	}
	cfg.estimators = unique(cfg.estimators)

	for _, name := range splitCSV(profileCSV) {
		p, ok := profiles[name]
		if !ok {
			return cfg, fmt.Errorf("unknown profile %q", name)
		}
		cfg.profiles = append(cfg.profiles, p)
	}
	if len(cfg.profiles) == 0 {
		return cfg, fmt.Errorf("need at least one profile")
	}

	for _, s := range splitCSV(rateCSV) {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			return cfg, fmt.Errorf("invalid passive rate %q", s)
		}
		cfg.passiveRates = append(cfg.passiveRates, v)
	}
	if len(cfg.passiveRates) == 0 {
		return cfg, fmt.Errorf("need at least one passive rate")
	}
	if cfg.repeats <= 0 {
		cfg.repeats = 1
	}
	return cfg, nil
}

func runAll(ctx context.Context, cfg config) []result {
	var results []result
	for _, c := range cfg.cases {
		switch c {
		case "cp3", "cp4", "cp5", "cp6", "cp7":
			results = append(results, runSelectorSim(cfg, c)...)
		}
	}
	if !contains(cfg.cases, "cp1") && !contains(cfg.cases, "cp2") {
		if cfg.jsonl {
			for _, r := range results {
				_ = json.NewEncoder(os.Stdout).Encode(r)
			}
		}
		return results
	}
	for _, p := range cfg.profiles {
		profileCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
		cleanup, err := chaos.Apply(p.Prof)
		if err != nil {
			cancel()
			for _, c := range cfg.cases {
				results = append(results, result{
					Case:           c,
					Profile:        p.Name,
					GroundTruthBPS: p.Prof.Bandwidth,
					Error:          "apply profile: " + err.Error(),
				})
			}
			continue
		}
		for _, c := range cfg.cases {
			switch c {
			case "cp1":
				results = append(results, runCP1(profileCtx, cfg, p)...)
			case "cp2":
				results = append(results, runCP2(profileCtx, cfg, p)...)
			case "cp3", "cp4", "cp5", "cp6", "cp7":
				continue
			}
		}
		if err := cleanup(); err != nil {
			results = append(results, result{Profile: p.Name, Error: "cleanup profile: " + err.Error()})
		}
		cancel()
	}
	if cfg.jsonl {
		for _, r := range results {
			_ = json.NewEncoder(os.Stdout).Encode(r)
		}
	}
	return results
}

func runCP1(ctx context.Context, cfg config, p profileSpec) []result {
	var out []result
	for _, est := range cfg.estimators {
		if est == "passive" {
			continue
		}
		for i := 1; i <= cfg.repeats; i++ {
			out = append(out, runEstimator(ctx, cfg, p, "cp1", est, i, 0))
		}
	}
	return out
}

func runCP2(ctx context.Context, cfg config, p profileSpec) []result {
	if !contains(cfg.estimators, "passive") {
		return nil
	}
	var out []result
	for _, rate := range cfg.passiveRates {
		for i := 1; i <= cfg.repeats; i++ {
			out = append(out, runEstimator(ctx, cfg, p, "cp2", "passive", i, rate))
		}
	}
	return out
}

func runSelectorSim(cfg config, caseName string) []result {
	var out []result
	for _, est := range cfg.estimators {
		for i := 1; i <= cfg.repeats; i++ {
			out = append(out, simulateSelector(cfg, caseName, est, i))
		}
	}
	return out
}

func simulateSelector(cfg config, caseName, estimator string, repeat int) result {
	r := result{
		Case:      caseName,
		Estimator: estimator,
		Repeat:    repeat,
	}
	active := profiles["A-lowlat-5M"]
	activeUseful := effectiveCapacity(active.Prof)
	bulk := true
	candidates := []profileSpec{profiles["B-bulk-50M"], profiles["C-bulk-50M"]}
	topK := 2
	switch caseName {
	case "cp3":
		r.Profile = "A-lowlat-5M+B-bulk-50M+C-bulk-50M"
	case "cp4":
		r.Profile = "interactive:A-lowlat-5M+B-bulk-50M+C-bulk-50M"
		bulk = false
	case "cp5":
		r.Profile = "A-lowlat-5M+stale(B,C)->evening"
		candidates = []profileSpec{profiles["B-evening"], profiles["C-evening"]}
	case "cp6":
		r.Profile = "A-lowlat-5M+bad-candidate"
		candidates = []profileSpec{profiles["bad-candidate"]}
	case "cp7":
		r.Profile = "A-lowlat-5M+10-candidates"
		candidates = manyCandidates()
		topK = 2
	default:
		r.Error = "unknown selector sim case"
		return r
	}

	var estimates []pathEstimate
	if estimator == "passive" {
		if caseName == "cp5" {
			r.Notes = "passive-only: stale high-capacity hints are low-confidence"
		} else {
			r.Notes = "passive-only: idle candidates remain low-confidence"
		}
	} else if !bulk {
		r.Notes = "interactive: capacity probes suppressed"
	} else {
		ordered := rankCandidates(candidates)
		if len(ordered) > topK {
			ordered = ordered[:topK]
		}
		for _, p := range ordered {
			pe := simulateEstimate(cfg, estimator, p)
			estimates = append(estimates, pe)
			r.ProbeBytes += pe.ProbeBytes
			r.ElapsedMS += pe.ElapsedMS
		}
	}

	estBPS, conf := aggregateCandidate(estimates)
	r.EstimateBPS = estBPS
	r.Confidence = conf
	r.GroundTruthBPS = int64(aggregateTruth(candidates))
	if r.GroundTruthBPS > 0 && r.EstimateBPS > 0 {
		r.ErrorPct = absPct(r.EstimateBPS, float64(r.GroundTruthBPS))
	}
	decision := pickTarget(bulk, activeUseful, estimates)
	if bulk && len(estimates) == 0 && aggregateTruth(candidates) > activeUseful*1.5 {
		decision.FalseDemotion = true
	}
	r.SelectedTarget = decision.Target
	r.Promoted = decision.Promote
	r.FalsePromotion = decision.FalsePromotion
	r.FalseDemotion = decision.FalseDemotion
	r.FlapCount = decision.FlapCount
	if r.Notes == "" {
		r.Notes = decision.Reason
	} else {
		r.Notes += "; " + decision.Reason
	}
	return r
}

type pathEstimate struct {
	Name       string
	Estimate   float64
	Truth      float64
	Confidence float64
	ProbeBytes int64
	ElapsedMS  int64
	QualityOK  bool
}

type selectorDecision struct {
	Target         string
	Promote        bool
	FalsePromotion bool
	FalseDemotion  bool
	FlapCount      int
	Reason         string
}

func simulateEstimate(cfg config, estimator string, p profileSpec) pathEstimate {
	truth := effectiveCapacity(p.Prof)
	pe := pathEstimate{
		Name:      p.Name,
		Truth:     truth,
		QualityOK: qualityOK(p.Prof),
	}
	switch estimator {
	case "bounded":
		pe.ProbeBytes = cfg.boundedBytes
		if pe.ProbeBytes <= 0 {
			pe.ProbeBytes = 1024 << 10
		}
		pe.Estimate = boundedModel(p.Prof, pe.ProbeBytes)
		pe.Confidence = confidenceFor(sample{bytes: pe.ProbeBytes, elapsed: time.Duration(pe.ProbeBytes*8) * time.Second / time.Duration(maxInt64(1, int64(pe.Estimate)))}, pe.ProbeBytes, true)
	case "adaptive":
		pe.Estimate, pe.ProbeBytes, pe.Confidence = adaptiveModel(cfg, p.Prof)
	case "trickle":
		pe.ProbeBytes = maxInt64(cfg.trickleBurst, 256<<10) * maxInt64(1, int64(cfg.trickleDur/maxDuration(cfg.trickleEvery, time.Millisecond)))
		pe.Estimate = trickleModel(p.Prof)
		pe.Confidence = 0.45
	case "calibration":
		pe.ProbeBytes = cfg.calibrateBytes
		if pe.ProbeBytes <= 0 {
			pe.ProbeBytes = 16 << 20
		}
		pe.Estimate = calibrationModel(p.Prof, pe.ProbeBytes)
		pe.Confidence = confidenceFor(sample{bytes: pe.ProbeBytes, elapsed: time.Duration(pe.ProbeBytes*8) * time.Second / time.Duration(maxInt64(1, int64(pe.Estimate)))}, pe.ProbeBytes, false)
	case "passive":
		pe.Estimate = 0
		pe.Confidence = 0.10
	default:
		pe.Estimate = 0
		pe.Confidence = 0
	}
	pe.Estimate = applyQualityPenalty(pe.Estimate, p.Prof)
	if !pe.QualityOK {
		pe.Confidence *= 0.55
	}
	pe.ElapsedMS = int64(float64(pe.ProbeBytes*8) / maxFloat(1, pe.Estimate) * 1000)
	if pe.ElapsedMS == 0 && pe.ProbeBytes > 0 {
		pe.ElapsedMS = 1
	}
	return pe
}

func boundedModel(p chaos.Profile, bytes int64) float64 {
	truth := effectiveCapacity(p)
	if truth <= 0 {
		return 0
	}
	bdp := truth * maxFloat(0.001, p.Delay.Seconds()*2) / 8
	if bdp < 256<<10 {
		bdp = 256 << 10
	}
	fill := clamp(float64(bytes) / (bdp * 1.5))
	return truth * (0.10 + 0.90*fill)
}

func trickleModel(p chaos.Profile) float64 {
	truth := effectiveCapacity(p)
	if truth <= 0 {
		return 0
	}
	if p.Bandwidth <= 8_000_000 && p.Delay <= 20*time.Millisecond {
		return truth * 1.8
	}
	bdp := truth * maxFloat(0.001, p.Delay.Seconds()*2) / 8
	if bdp > 512<<10 {
		return truth * 0.25
	}
	return truth * 0.60
}

func calibrationModel(p chaos.Profile, bytes int64) float64 {
	truth := effectiveCapacity(p)
	if truth <= 0 {
		return 0
	}
	bdp := truth * maxFloat(0.001, p.Delay.Seconds()*2) / 8
	if bdp <= 0 {
		return truth
	}
	fill := clamp(float64(bytes) / (bdp * 2))
	return truth * (0.55 + 0.45*fill)
}

func adaptiveModel(cfg config, p chaos.Profile) (estimate float64, probeBytes int64, confidence float64) {
	size := cfg.adaptiveMin
	if size <= 0 {
		size = 256 << 10
	}
	maxSize := cfg.adaptiveMax
	if maxSize < size {
		maxSize = size
	}
	truth := effectiveCapacity(p)
	var prev float64
	var rates []float64
	for size <= maxSize {
		cur := boundedModel(p, size)
		rates = append(rates, cur)
		probeBytes += size
		estimate = cur
		if prev > 0 && relChange(prev, cur) <= maxFloat(0.05, cfg.adaptiveEps) && size >= 1024<<10 {
			break
		}
		prev = cur
		if size == maxSize {
			break
		}
		size *= 2
		if size > maxSize {
			size = maxSize
		}
	}
	if truth > 0 && estimate > truth*1.10 {
		estimate = truth * 1.10
	}
	confidence = adaptiveConfidence(sample{bytes: probeBytes, elapsed: time.Duration(probeBytes*8) * time.Second / time.Duration(maxInt64(1, int64(maxFloat(1, estimate))))}, probeBytes, rates)
	return estimate, probeBytes, confidence
}

func effectiveCapacity(p chaos.Profile) float64 {
	capacity := float64(p.Bandwidth)
	if capacity <= 0 {
		return 0
	}
	lossPenalty := 1 - p.LossPct/100*8
	if lossPenalty < 0.05 {
		lossPenalty = 0.05
	}
	jitterPenalty := 1.0
	if p.Jitter > 0 {
		jitterPenalty -= p.Jitter.Seconds() / 0.5
		if jitterPenalty < 0.35 {
			jitterPenalty = 0.35
		}
	}
	return capacity * lossPenalty * jitterPenalty
}

func applyQualityPenalty(v float64, p chaos.Profile) float64 {
	if p.LossPct >= 2.0 {
		v *= 0.65
	}
	if p.Jitter >= 50*time.Millisecond {
		v *= 0.75
	}
	return v
}

func qualityOK(p chaos.Profile) bool {
	return p.LossPct < 2.0 && p.Jitter < 50*time.Millisecond && p.Delay < 180*time.Millisecond
}

func aggregateCandidate(estimates []pathEstimate) (float64, float64) {
	if len(estimates) == 0 {
		return 0, 0
	}
	var total, conf float64
	for _, e := range estimates {
		if e.QualityOK {
			total += e.Estimate
		}
		conf += e.Confidence
	}
	return total, conf / float64(len(estimates))
}

func aggregateTruth(candidates []profileSpec) float64 {
	var total float64
	for _, c := range candidates {
		if qualityOK(c.Prof) {
			total += effectiveCapacity(c.Prof)
		}
	}
	return total
}

func pickTarget(bulk bool, activeUseful float64, estimates []pathEstimate) selectorDecision {
	if !bulk {
		return selectorDecision{Target: "A", Reason: "interactive flow stays on low-latency active path"}
	}
	est, conf := aggregateCandidate(estimates)
	truth := 0.0
	names := make([]string, 0, len(estimates))
	for _, e := range estimates {
		if e.QualityOK {
			truth += e.Truth
			names = append(names, e.Name)
		}
	}
	if len(estimates) == 0 {
		return selectorDecision{
			Target:        "A",
			FalseDemotion: truth > activeUseful*1.5,
			Reason:        "no candidate capacity evidence",
		}
	}
	enoughConfidence := conf >= 0.60 || (conf >= 0.50 && est >= activeUseful*4)
	if enoughConfidence && est >= activeUseful*1.5 && len(names) > 0 {
		falsePromotion := truth < activeUseful*0.90
		return selectorDecision{
			Target:         strings.Join(names, "+"),
			Promote:        true,
			FalsePromotion: falsePromotion,
			Reason:         fmt.Sprintf("promote: estimate %.1fM confidence %.2f", est/1_000_000, conf),
		}
	}
	return selectorDecision{
		Target:        "A",
		FalseDemotion: truth > activeUseful*1.5,
		Reason:        fmt.Sprintf("stay: estimate %.1fM confidence %.2f", est/1_000_000, conf),
	}
}

func rankCandidates(in []profileSpec) []profileSpec {
	out := append([]profileSpec(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if qualityOK(out[i].Prof) != qualityOK(out[j].Prof) {
			return qualityOK(out[i].Prof)
		}
		return effectiveCapacity(out[i].Prof) > effectiveCapacity(out[j].Prof)
	})
	return out
}

func manyCandidates() []profileSpec {
	out := []profileSpec{
		profiles["B-bulk-50M"],
		profiles["C-bulk-50M"],
		profiles["B-evening"],
		profiles["C-evening"],
		profiles["bad-candidate"],
	}
	for i := 0; i < 5; i++ {
		out = append(out, profileSpec{
			Name: fmt.Sprintf("low-priority-%d", i+1),
			Prof: chaos.Profile{
				Bandwidth: 3_000_000 + int64(i)*1_000_000,
				Delay:     time.Duration(40+i*15) * time.Millisecond,
				Jitter:    time.Duration(5+i*5) * time.Millisecond,
				LossPct:   float64(i) * 0.2,
			},
		})
	}
	return out
}

func runEstimator(ctx context.Context, cfg config, p profileSpec, caseName, estimator string, repeat int, appRate int64) result {
	r := result{
		Case:           caseName,
		Estimator:      estimator,
		Profile:        p.Name,
		Repeat:         repeat,
		AppRateBPS:     appRate,
		GroundTruthBPS: p.Prof.Bandwidth,
	}
	before, beforeOK := readProcessUsage()
	start := time.Now()

	var s sample
	var probeBytes int64
	var appBytes int64
	var confidence float64
	var notes string
	var err error

	switch estimator {
	case "passive":
		bytes := cfg.calibrateBytes / 2
		pace := appRate
		if appRate > 0 {
			bytes = appRate / 8 * int64(cfg.passiveDur/time.Second)
			if bytes < 256<<10 {
				bytes = 256 << 10
			}
		}
		s, err = transfer(ctx, bytes, pace)
		appBytes = s.bytes
		if appRate > 0 {
			confidence = 0.25
			notes = "app-limited; useful-rate sample, not capacity"
		} else {
			confidence = confidenceFor(s, bytes, false)
			notes = "unbounded application sample"
		}
	case "bounded":
		s, err = transfer(ctx, cfg.boundedBytes, 0)
		probeBytes = s.bytes
		confidence = confidenceFor(s, cfg.boundedBytes, true)
	case "adaptive":
		s, probeBytes, confidence, notes, err = adaptive(ctx, cfg)
	case "trickle":
		s, probeBytes, err = trickle(ctx, cfg)
		confidence = 0.45
		notes = "max of repeated small probes"
	case "calibration":
		s, err = transfer(ctx, cfg.calibrateBytes, 0)
		probeBytes = s.bytes
		confidence = confidenceFor(s, cfg.calibrateBytes, false)
	}

	elapsed := time.Since(start)
	after, afterOK := readProcessUsage()
	r.ElapsedMS = elapsed.Milliseconds()
	r.AppBytes = appBytes
	r.ProbeBytes = probeBytes
	r.Confidence = confidence
	r.Notes = notes
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if s.elapsed > 0 {
		r.EstimateBPS = float64(s.bytes*8) / s.elapsed.Seconds()
	}
	if p.Prof.Bandwidth > 0 {
		r.ErrorPct = absPct(r.EstimateBPS, float64(p.Prof.Bandwidth))
	}
	if beforeOK && afterOK {
		cpu := after.sub(before)
		r.UserCPUMS = cpu.User.Milliseconds()
		r.SysCPUMS = cpu.Sys.Milliseconds()
		if elapsed > 0 {
			r.CPUPct = float64(cpu.User+cpu.Sys) / float64(elapsed) * 100
		}
	}
	return r
}

func transfer(ctx context.Context, totalBytes int64, paceBPS int64) (sample, error) {
	if totalBytes <= 0 {
		return sample{}, fmt.Errorf("transfer bytes must be positive")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return sample{}, err
	}
	defer ln.Close()

	done := make(chan sample, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 128<<10)
		var got int64
		var first time.Time
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if first.IsZero() {
					first = time.Now()
				}
				got += int64(n)
			}
			if err != nil {
				if err == io.EOF {
					if first.IsZero() {
						first = time.Now()
					}
					done <- sample{bytes: got, elapsed: time.Since(first)}
					return
				}
				errc <- err
				return
			}
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return sample{}, err
	}
	buf := make([]byte, 64<<10)
	var sent int64
	start := time.Now()
	for sent < totalBytes {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return sample{}, ctx.Err()
		default:
		}
		n := int64(len(buf))
		if rem := totalBytes - sent; rem < n {
			n = rem
		}
		w, err := conn.Write(buf[:n])
		if w > 0 {
			sent += int64(w)
			if paceBPS > 0 {
				wantElapsed := time.Duration(float64(sent*8) / float64(paceBPS) * float64(time.Second))
				if sleep := start.Add(wantElapsed).Sub(time.Now()); sleep > 0 {
					timer := time.NewTimer(sleep)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						_ = conn.Close()
						return sample{}, ctx.Err()
					}
				}
			}
		}
		if err != nil {
			_ = conn.Close()
			return sample{}, err
		}
	}
	_ = conn.Close()

	select {
	case s := <-done:
		return s, nil
	case err := <-errc:
		return sample{}, err
	case <-ctx.Done():
		return sample{}, ctx.Err()
	}
}

func trickle(ctx context.Context, cfg config) (sample, int64, error) {
	deadline := time.Now().Add(cfg.trickleDur)
	var totalBytes int64
	var best sample
	for time.Now().Before(deadline) {
		s, err := transfer(ctx, cfg.trickleBurst, 0)
		if err != nil {
			return sample{}, totalBytes, err
		}
		totalBytes += s.bytes
		if best.elapsed == 0 || rate(s) > rate(best) {
			best = s
		}
		sleep := time.Until(deadline)
		if sleep > cfg.trickleEvery {
			sleep = cfg.trickleEvery
		}
		if sleep > 0 {
			timer := time.NewTimer(sleep)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return sample{}, totalBytes, ctx.Err()
			}
		}
	}
	if best.elapsed == 0 {
		return sample{}, totalBytes, fmt.Errorf("no trickle samples")
	}
	return best, totalBytes, nil
}

func adaptive(ctx context.Context, cfg config) (sample, int64, float64, string, error) {
	size := cfg.adaptiveMin
	if size <= 0 {
		size = 256 << 10
	}
	maxSize := cfg.adaptiveMax
	if maxSize < size {
		maxSize = size
	}
	eps := cfg.adaptiveEps
	if eps <= 0 {
		eps = 0.20
	}

	var totalBytes int64
	var last sample
	var prevRate float64
	var rates []float64
	var rounds []string
	for size <= maxSize {
		s, err := transfer(ctx, size, 0)
		if err != nil {
			return sample{}, totalBytes, 0, "", err
		}
		totalBytes += s.bytes
		curRate := rate(s)
		rates = append(rates, curRate)
		rounds = append(rounds, fmt.Sprintf("%dKiB=%.1fM", size>>10, curRate/1_000_000))
		last = s
		if prevRate > 0 && s.elapsed >= 1500*time.Millisecond {
			if relChange(prevRate, curRate) <= eps {
				return last, totalBytes, adaptiveConfidence(last, totalBytes, rates), "adaptive stop: " + strings.Join(rounds, " "), nil
			}
		}
		prevRate = curRate
		if size == maxSize {
			break
		}
		size *= 2
		if size > maxSize {
			size = maxSize
		}
	}
	if last.elapsed == 0 {
		return sample{}, totalBytes, 0, "", fmt.Errorf("no adaptive samples")
	}
	return last, totalBytes, adaptiveConfidence(last, totalBytes, rates), "adaptive max: " + strings.Join(rounds, " "), nil
}

func adaptiveConfidence(s sample, totalBytes int64, rates []float64) float64 {
	c := confidenceFor(s, totalBytes, false)
	drops := 0
	for i := 1; i < len(rates); i++ {
		if rates[i] < rates[i-1]*0.80 {
			drops++
		}
	}
	if len(rates) > 0 {
		maxRate := rates[0]
		for _, r := range rates[1:] {
			if r > maxRate {
				maxRate = r
			}
		}
		if maxRate > 0 && rates[len(rates)-1] < maxRate*0.75 {
			drops++
		}
	}
	for ; drops > 0; drops-- {
		c *= 0.70
	}
	if c < 0.10 {
		c = 0.10
	}
	return c
}

func confidenceFor(s sample, planned int64, smallProbe bool) float64 {
	if s.elapsed <= 0 || planned <= 0 {
		return 0
	}
	seconds := s.elapsed.Seconds()
	sizeScore := float64(planned) / float64(8<<20)
	if smallProbe {
		sizeScore = float64(planned) / float64(4<<20)
	}
	timeScore := seconds / 3
	c := 0.20 + 0.45*clamp(sizeScore) + 0.35*clamp(timeScore)
	if smallProbe && c > 0.75 {
		c = 0.75
	}
	if c > 0.95 {
		c = 0.95
	}
	return c
}

func relChange(a, b float64) float64 {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	den := a
	if b > den {
		den = b
	}
	if den == 0 {
		return 0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff / den
}

func rate(s sample) float64 {
	if s.elapsed <= 0 {
		return 0
	}
	return float64(s.bytes*8) / s.elapsed.Seconds()
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func absPct(got, want float64) float64 {
	if want == 0 {
		return 0
	}
	if got > want {
		return (got - want) / want * 100
	}
	return (want - got) / want * 100
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func printSummary(results []result) {
	fmt.Println()
	fmt.Println("capacity probe summary")
	fmt.Println("case  profile         estimator    app_bps   est_mbps  truth_mbps  err%    conf  probe_kib  app_kib  elapsed_ms  selected         fp  fd  note/error")
	for _, r := range results {
		note := r.Notes
		if r.Error != "" {
			note = r.Error
		}
		fmt.Printf("%-5s %-15s %-12s %-9d %-9.2f %-11.2f %-7.1f %-5.2f %-10.1f %-8.1f %-11d %-16s %-3t %-3t %s\n",
			r.Case, r.Profile, r.Estimator, r.AppRateBPS,
			r.EstimateBPS/1_000_000, float64(r.GroundTruthBPS)/1_000_000,
			r.ErrorPct, r.Confidence, float64(r.ProbeBytes)/1024,
			float64(r.AppBytes)/1024, r.ElapsedMS, r.SelectedTarget, r.FalsePromotion, r.FalseDemotion, note)
	}

	type key struct {
		caseName  string
		estimator string
	}
	type agg struct {
		n        int
		errPct   float64
		probeKiB float64
	}
	aggs := map[key]agg{}
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		k := key{caseName: r.Case, estimator: r.Estimator}
		a := aggs[k]
		a.n++
		a.errPct += r.ErrorPct
		a.probeKiB += float64(r.ProbeBytes) / 1024
		aggs[k] = a
	}
	var keys []key
	for k := range aggs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].caseName != keys[j].caseName {
			return keys[i].caseName < keys[j].caseName
		}
		return keys[i].estimator < keys[j].estimator
	})
	if len(keys) > 0 {
		fmt.Println()
		fmt.Println("averages")
		fmt.Println("case  estimator    runs  avg_err%  avg_probe_kib")
		for _, k := range keys {
			a := aggs[k]
			fmt.Printf("%-5s %-12s %-5d %-9.1f %-13.1f\n",
				k.caseName, k.estimator, a.n, a.errPct/float64(a.n), a.probeKiB/float64(a.n))
		}
	}
}
