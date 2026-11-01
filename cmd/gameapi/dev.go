package main

// 開発モード: WAFDY_DEV=1 で起動すると、AWS なしで画面を確かめられるローカルサーバーになる。
//   - 保存先はメモリ上
//   - 攻撃は実際には送らず、ラボは模範解答のルールを評価器で当てた結果、
//     チュートリアルとゲームはおおよその結果を採点結果として返す

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"wafdy/internal/scenario"
	"wafdy/internal/score"
	"wafdy/internal/store"
)

type memStore struct {
	mu    sync.Mutex
	runs  map[string]store.Run
	bests map[string]store.Best
	locks map[string]string
	// contest は今の競技。contestBests は競技ごとの記録 (キーは競技 ID/プレイヤー/問題)。
	contest      *store.Contest
	contestBests map[string]store.Best
}

func newMemStore() *memStore {
	return &memStore{runs: map[string]store.Run{}, bests: map[string]store.Best{}, locks: map[string]string{}, contestBests: map[string]store.Best{}}
}

func (m *memStore) GetRun(_ context.Context, id string) (*store.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (m *memStore) CreateRun(_ context.Context, run *store.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = *run
	return nil
}

func (m *memStore) update(id string, f func(*store.Run)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	f(&r)
	m.runs[id] = r
}

func (m *memStore) FinishRun(_ context.Context, id string, res *score.Result, runErr error) error {
	m.update(id, func(r *store.Run) {
		r.Status, r.Result = store.StatusDone, res
		if runErr != nil {
			r.Status, r.Error = store.StatusFailed, runErr.Error()
		}
	})
	return nil
}

func (m *memStore) AcquireLock(_ context.Context, player, runID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.locks[player]; ok {
		return store.ErrLocked
	}
	m.locks[player] = runID
	return nil
}

func (m *memStore) ReleaseLock(_ context.Context, player, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks[player] == runID {
		delete(m.locks, player)
	}
	return nil
}

func (m *memStore) GetBest(_ context.Context, player, scenarioID string) (*store.Best, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bests[player+"/"+scenarioID]
	if !ok {
		return nil, nil
	}
	return &b, nil
}

func (m *memStore) ListBest(context.Context) ([]store.Best, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Best, 0, len(m.bests))
	for _, b := range m.bests {
		out = append(out, b)
	}
	return out, nil
}

func (m *memStore) recordBest(b store.Best) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b.UpdatedAt = time.Now().Unix()
	bests, key := m.bests, b.Player+"/"+b.ScenarioID
	if b.Contest != "" {
		bests, key = m.contestBests, b.Contest+"/"+key
	}
	if old, ok := bests[key]; !ok || old.Score < b.Score {
		bests[key] = b
	}
}

func (m *memStore) ListContestBest(_ context.Context, contestID string) ([]store.Best, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Best
	for _, b := range m.contestBests {
		if b.Contest == contestID {
			out = append(out, b)
		}
	}
	return out, nil
}

func (m *memStore) GetContest(context.Context) (*store.Contest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.contest == nil {
		return nil, nil
	}
	c := *m.contest
	return &c, nil
}

func (m *memStore) PutContest(_ context.Context, c *store.Contest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	m.contest = &cp
	return nil
}

func (m *memStore) DeleteContest(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.contest = nil
	return nil
}

// devInvoker はトラフィック生成 Lambda の代わりに、その場で採点する。
type devInvoker struct{ store *memStore }

func (d devInvoker) Invoke(_ context.Context, in *awslambda.InvokeInput, _ ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error) {
	var p struct {
		RunID, Player, ScenarioID, ContestID string
		HintUsed, Recon                      bool
	}
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		return nil, err
	}
	go d.run(p.RunID, p.Player, p.ScenarioID, p.ContestID, p.HintUsed, p.Recon)
	return &awslambda.InvokeOutput{StatusCode: http.StatusAccepted}, nil
}

func (d devInvoker) run(id, player, scenarioID, contestID string, hintUsed, recon bool) {
	sc, _ := scenario.Get(scenarioID)
	d.store.update(id, func(r *store.Run) { r.Status, r.StartedAt = store.StatusRunning, time.Now().UnixMilli() })
	time.Sleep(3 * time.Second)

	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	var outcomes []score.Outcome
	for i, p := range sc.Patterns {
		for n := 0; n < p.Count; n++ {
			blocked := false
			if recon {
				blocked = false // 偵察では何もブロックしない (Count のルールだけ)
			} else if sc.HasReference() {
				blocked, _ = sc.ReferenceBlocks(p.Make(rng))
			} else {
				blocked = p.Kind == scenario.Attack && rng.IntN(10) < 9
			}
			outcomes = append(outcomes, score.Outcome{Kind: p.Kind, Key: strconv.Itoa(i), Label: p.Label, Blocked: blocked, Scored: true})
		}
	}
	res := score.Compute(outcomes, hintUsed)
	if !recon {
		best := store.Best{Player: player, ScenarioID: scenarioID, Score: res.Score, HintUsed: hintUsed, RunID: id}
		d.store.recordBest(best)
		if contestID != "" {
			best.Contest = contestID
			d.store.recordBest(best)
		}
	}
	_ = d.store.FinishRun(context.Background(), id, &res, nil)
	_ = d.store.ReleaseLock(context.Background(), player, id)
}

func runDev(addr string) {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	mem := newMemStore()
	a := &app{store: mem, lambda: devInvoker{mem}, players: []string{"player1", "player2"}, region: "ap-northeast-1", project: "wafdojo", cloudFront: true}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := events.LambdaFunctionURLRequest{RawPath: r.URL.Path, Body: string(body), Headers: map[string]string{}, QueryStringParameters: map[string]string{}}
		req.RequestContext.HTTP.Method = r.Method
		for k, v := range r.Header {
			req.Headers[strings.ToLower(k)] = v[0]
		}
		for k, v := range r.URL.Query() {
			req.QueryStringParameters[k] = v[0]
		}
		res, err := a.handle(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for k, v := range res.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(res.StatusCode)
		if res.IsBase64Encoded {
			b, _ := base64.StdEncoding.DecodeString(res.Body)
			w.Write(b)
			return
		}
		io.WriteString(w, res.Body)
	})
	log.Printf("WAF Dojo dev server: http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
