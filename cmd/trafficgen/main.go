// trafficgen はシナリオに沿ったリクエストを、そのプレイヤー専用の ALB にだけ送り、採点する。
// 送信先は Terraform が環境変数 TARGETS (ALB) と TARGETS_CLOUDFRONT (CloudFront) に設定した、
// そのプレイヤー自身の環境に限られ、外から指定することはできない。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"wafdy/internal/scenario"
	"wafdy/internal/score"
	"wafdy/internal/store"
	"wafdy/internal/tlsprofile"
)

const maxConcurrency = 32

type Payload struct {
	RunID      string `json:"runId"`
	Player     string `json:"player"`
	ScenarioID string `json:"scenarioId"`
	HintUsed   bool   `json:"hintUsed"`
	Recon      bool   `json:"recon"`
	// ContestID は競技中の実行のときだけ入る。練習の記録に加えて、競技の記録も残す。
	ContestID string `json:"contestId,omitempty"`
}

type job struct {
	at      time.Duration
	key     string
	pattern *scenario.Pattern
	req     scenario.Request
}

var (
	targets   map[string]string
	cfTargets map[string]string
	st        *store.Store

	clientsMu sync.Mutex
	clients   = map[tlsprofile.Name]*http.Client{}
)

// clientFor は TLS プロファイルごとの HTTP クライアントを返す。
// JA4 は接続ごとに決まるので、プロファイルごとに接続プールを分ける。
func clientFor(name tlsprofile.Name) *http.Client {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[name]; ok {
		return c
	}
	c := &http.Client{
		Transport: tlsprofile.Transport(name),
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	clients[name] = c
	return c
}

func handler(ctx context.Context, p Payload) error {
	defer func() {
		if err := st.ReleaseLock(context.WithoutCancel(ctx), p.Player, p.RunID); err != nil {
			log.Printf("release lock: %v", err)
		}
	}()

	res, err := execute(ctx, p)
	if err != nil {
		log.Printf("run %s failed: %v", p.RunID, err)
	}
	// 画面は FinishRun を見て結果を表示し、すぐ模範解答を取りに来るので、ベストスコアを先に記録する
	if err == nil && !p.Recon { // 偵察は採点しないので記録しない
		best := store.Best{Player: p.Player, ScenarioID: p.ScenarioID, Score: res.Score, HintUsed: p.HintUsed, RunID: p.RunID}
		if berr := st.RecordBest(ctx, best); berr != nil {
			err = berr
		}
		if p.ContestID != "" && err == nil {
			best.Contest = p.ContestID
			err = st.RecordBest(ctx, best)
		}
	}
	return st.FinishRun(context.WithoutCancel(ctx), p.RunID, res, err)
}

func execute(ctx context.Context, p Payload) (*score.Result, error) {
	sc, ok := scenario.Get(p.ScenarioID)
	if !ok {
		return nil, fmt.Errorf("unknown scenario %q", p.ScenarioID)
	}
	target, ok := targets[p.Player]
	if sc.Target == scenario.TargetCloudFront {
		target, ok = cfTargets[p.Player]
		if !ok {
			return nil, fmt.Errorf("CloudFront is not enabled for player %q", p.Player)
		}
	}
	if !ok {
		return nil, fmt.Errorf("unknown player %q", p.Player)
	}
	if err := st.MarkRunning(ctx, p.RunID, time.Now()); err != nil {
		return nil, err
	}
	outcomes := run(ctx, target, sc)
	res := score.Compute(outcomes, p.HintUsed)
	return &res, nil
}

// schedule は各パターンのリクエストを Duration の間に均等に並べ、時刻順にする。
func schedule(sc *scenario.Scenario, rng *rand.Rand) []job {
	var jobs []job
	for i := range sc.Patterns {
		p := &sc.Patterns[i]
		interval := sc.Duration / time.Duration(p.Count)
		for n := 0; n < p.Count; n++ {
			at := interval*time.Duration(n) + time.Duration(rng.Int64N(int64(interval)))
			jobs = append(jobs, job{at: at, key: strconv.Itoa(i), pattern: p, req: p.Make(rng)})
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].at < jobs[j].at })
	return jobs
}

func run(ctx context.Context, target string, sc *scenario.Scenario) []score.Outcome {
	jobs := schedule(sc, rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())))
	outcomes := make([]score.Outcome, len(jobs))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	start := time.Now()

	for i, j := range jobs {
		if wait := j.at - time.Since(start); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
			}
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			blocked, err := send(ctx, target, j.req)
			if err != nil {
				log.Printf("%s %s: %v", j.req.MethodOrGet(), j.req.Path, err)
			}
			outcomes[i] = score.Outcome{
				Kind:    j.pattern.Kind,
				Key:     j.key,
				Label:   j.pattern.Label,
				Blocked: blocked,
				Err:     err != nil,
				Scored:  j.pattern.Kind == scenario.Benign || j.at >= sc.Warmup,
				At:      j.at,
			}
		}()
	}
	wg.Wait()
	return outcomes
}

// newRequest は、シナリオのパスとクエリを書き換えずにそのまま送る HTTP リクエストを作る。
func newRequest(ctx context.Context, target string, r scenario.Request) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, r.MethodOrGet(), target+r.Target(), strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Forwarded-For", r.ClientIP)
	return req, nil
}

// send は WAF にブロックされたかどうかを返す。
// ダミーアプリは常に 200 を返すので、4xx は WAF の Block / CAPTCHA、
// x-amzn-waf-action ヘッダーは Challenge / CAPTCHA とみなす。
// ただし 400 は ALB が不正なリクエストとして WAF より前に断ったものなので、ブロックとは数えない。
func send(ctx context.Context, target string, r scenario.Request) (bool, error) {
	req, err := newRequest(ctx, target, r)
	if err != nil {
		return false, err
	}
	resp, err := clientFor(r.TLSProfile()).Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	if resp.Header.Get("x-amzn-waf-action") != "" {
		return true, nil
	}
	switch {
	case resp.StatusCode == http.StatusBadRequest:
		return false, fmt.Errorf("rejected by the load balancer: %s", resp.Status)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return true, nil
	case resp.StatusCode >= 500:
		return false, fmt.Errorf("server error: %s", resp.Status)
	}
	return false, nil
}

func main() {
	if err := json.Unmarshal([]byte(os.Getenv("TARGETS")), &targets); err != nil || len(targets) == 0 {
		log.Fatal(errors.Join(errors.New("TARGETS must be a JSON object of player -> ALB URL"), err))
	}
	if v := os.Getenv("TARGETS_CLOUDFRONT"); v != "" {
		if err := json.Unmarshal([]byte(v), &cfTargets); err != nil {
			log.Fatal(errors.Join(errors.New("TARGETS_CLOUDFRONT must be a JSON object of player -> CloudFront URL"), err))
		}
	}
	var err error
	if st, err = store.New(context.Background()); err != nil {
		log.Fatal(err)
	}
	lambda.Start(handler)
}
