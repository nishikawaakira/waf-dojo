package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"wafdy/internal/store"
)

// nopInvoker は攻撃を実際には始めない。
type nopInvoker struct{}

func (nopInvoker) Invoke(context.Context, *awslambda.InvokeInput, ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error) {
	return &awslambda.InvokeOutput{}, nil
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newContestApp() (*app, *memStore) {
	mem := newMemStore()
	return &app{
		store: mem, lambda: nopInvoker{}, players: []string{"player1", "player2"},
		tokenHashes: map[string]string{"player1": sha("tok-1"), "player2": sha("tok-2")},
		adminHash:   sha("admin"),
	}, mem
}

func call(t *testing.T, a *app, method, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req := events.LambdaFunctionURLRequest{RawPath: path, Body: body, Headers: headers, QueryStringParameters: map[string]string{"lang": "en"}}
	req.RequestContext.HTTP.Method = method
	res, err := a.handle(context.Background(), req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(res.Body), &out)
	return res.StatusCode, out
}

var (
	asAdmin   = map[string]string{"x-wafdy-admin": "admin"}
	asPlayer1 = map[string]string{"x-wafdy-token": "tok-1"}
)

func TestContestFlow(t *testing.T) {
	a, mem := newContestApp()
	const lab, other = "lab-1-log4shell", "lab-2-graphql-introspection"

	// 管理者以外は競技を開けない
	if code, _ := call(t, a, http.MethodPut, "/api/admin/contest", `{"scenarios":["`+lab+`"]}`, asPlayer1); code != http.StatusForbidden {
		t.Fatalf("player opened a contest: %d", code)
	}
	// チュートリアルや存在しない問題は出題できない
	for _, bad := range []string{`{"scenarios":["tutorial-1-sqli"]}`, `{"scenarios":["nope"]}`, `{"scenarios":[]}`, `{"scenarios":["` + lab + `"],"minutes":-1}`} {
		if code, _ := call(t, a, http.MethodPut, "/api/admin/contest", bad, asAdmin); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", bad, code)
		}
	}
	code, out := call(t, a, http.MethodPut, "/api/admin/contest", `{"title":"WAF Cup","scenarios":["`+lab+`","`+lab+`"],"minutes":30}`, asAdmin)
	if code != http.StatusOK {
		t.Fatalf("open contest: %d %v", code, out)
	}
	c := mem.contest
	if len(c.Scenarios) != 1 || c.Title != "WAF Cup" || c.EndsAt == 0 {
		t.Fatalf("contest = %+v (duplicates should be removed, end time set)", c)
	}

	// チュートリアルをクリアしていなくても、出題された問題だけは挑戦できる
	if code, out := call(t, a, http.MethodPost, "/api/runs", `{"scenarioId":"`+lab+`"}`, asPlayer1); code != http.StatusAccepted {
		t.Fatalf("contest problem: %d %v", code, out)
	}
	_ = mem.ReleaseLock(context.Background(), "player1", mem.locks["player1"])
	if code, _ := call(t, a, http.MethodPost, "/api/runs", `{"scenarioId":"`+other+`"}`, asPlayer1); code != http.StatusForbidden {
		t.Errorf("problem outside the contest: got %d, want 403", code)
	}
	// 競技中は、挑戦済みでも模範解答は見られない
	mem.recordBest(store.Best{Player: "player1", ScenarioID: lab, Score: 100})
	if code, _ := call(t, a, http.MethodGet, "/api/scenarios/"+lab+"/solution", "", asPlayer1); code != http.StatusForbidden {
		t.Errorf("solution during the contest: got %d, want 403", code)
	}

	// 終了すると攻撃は開始できず、模範解答は挑戦していなくても見られる
	if code, _ := call(t, a, http.MethodPost, "/api/admin/contest/end", "", asAdmin); code != http.StatusOK {
		t.Fatalf("end contest: %d", code)
	}
	if code, _ := call(t, a, http.MethodPost, "/api/runs", `{"scenarioId":"`+lab+`"}`, asPlayer1); code != http.StatusForbidden {
		t.Errorf("run after the end: got %d, want 403", code)
	}
	if code, _ := call(t, a, http.MethodGet, "/api/scenarios/"+lab+"/solution", "", map[string]string{"x-wafdy-token": "tok-2"}); code != http.StatusOK {
		t.Errorf("solution after the end: got %d, want 200", code)
	}

	// 終了時刻を変えると再開できる
	if code, _ := call(t, a, http.MethodPatch, "/api/admin/contest", `{"minutes":10}`, asAdmin); code != http.StatusOK || !mem.contest.Running(time.Now()) {
		t.Errorf("extend: %d, running %v", code, mem.contest.Running(time.Now()))
	}
	// 通常モードに戻すと、チュートリアルが必要に戻る
	if code, _ := call(t, a, http.MethodDelete, "/api/admin/contest", "", asAdmin); code != http.StatusOK || mem.contest != nil {
		t.Fatalf("back to normal: %d", code)
	}
	if code, _ := call(t, a, http.MethodPost, "/api/runs", `{"scenarioId":"`+lab+`"}`, asPlayer1); code != http.StatusForbidden {
		t.Errorf("after the contest, tutorials are required again: got %d", code)
	}
}

func TestContestTimeLimit(t *testing.T) {
	c := &store.Contest{EndsAt: time.Now().Add(-time.Second).UnixMilli()}
	if c.Running(time.Now()) {
		t.Error("a contest past its end time must not be running")
	}
	if !(&store.Contest{}).Running(time.Now()) {
		t.Error("a contest without a time limit runs until ended")
	}
}

func TestSummarizeContest(t *testing.T) {
	c := &store.Contest{Scenarios: []string{"a", "b"}}
	bests := []store.Best{
		{Player: "early", ScenarioID: "a", Score: 100, UpdatedAt: 10},
		{Player: "late", ScenarioID: "a", Score: 100, UpdatedAt: 20},
		{Player: "late", ScenarioID: "x", Score: 100, UpdatedAt: 5}, // 出題されていない問題は数えない
		{Player: "top", ScenarioID: "a", Score: 90, UpdatedAt: 30},
		{Player: "top", ScenarioID: "b", Score: 50, UpdatedAt: 40},
	}
	got := summarizeContest([]string{"late", "early", "top", "zero"}, c, bests)
	order := []string{}
	for _, e := range got {
		order = append(order, e.Player)
	}
	want := []string{"top", "early", "late", "zero"} // 合計点、同点なら先に到達した人
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
	if got[0].Total != 140 || got[0].Solved != 1 {
		t.Errorf("top: total %d solved %d", got[0].Total, got[0].Solved)
	}
}
