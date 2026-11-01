package main

// 競技モード: 管理者が問題を選んで競技を開き、プレイヤーはその問題だけを解いて得点を競う。
//   - 競技中はチュートリアルなしで、出題された問題にだけ挑戦できる
//   - ヒントは見られる (×0.8)。模範解答は競技が終わるまで見られない
//   - 得点は競技ごとに記録する (練習の記録とは混ぜない)
//
//	GET    /api/contest              今の競技と、競技のランキング
//	PUT    /api/admin/contest        競技を開始する (管理者)
//	PATCH  /api/admin/contest        終了時刻を変える (管理者)
//	POST   /api/admin/contest/end    今すぐ終了する (管理者)
//	DELETE /api/admin/contest        通常モードに戻す (管理者)

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"wafdy/internal/scenario"
	"wafdy/internal/store"
)

// 競技の時間の上限 (分)。
const maxContestMinutes = 24 * 60

// isAdmin は管理者のトークン (X-Wafdy-Admin) が正しいかを返す。
// 管理者のトークンを設定していない場合は、プレイヤーのトークンもない (一人で遊ぶ・開発モード) ときだけ誰でも管理者になれる。
func (a *app) isAdmin(req events.LambdaFunctionURLRequest) bool {
	if a.adminHash == "" {
		return len(a.tokenHashes) == 0
	}
	token := req.Headers["x-wafdy-admin"]
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(a.adminHash)) == 1
}

// contestView は画面に返す競技の情報。
type contestView struct {
	*store.Contest
	// Status は running (攻撃を開始できる) か ended (終了。模範解答を公開)。
	Status string `json:"status"`
}

func viewContest(c *store.Contest, now time.Time) *contestView {
	if c == nil {
		return nil
	}
	v := &contestView{Contest: c, Status: "ended"}
	if c.Running(now) {
		v.Status = "running"
	}
	return v
}

type contestEntry struct {
	Player string `json:"player"`
	Total  int    `json:"total"`
	// Solved は MasteryScore 以上の問題の数。
	Solved int                   `json:"solved"`
	Scores map[string]store.Best `json:"scores"`
	// LastAt は最後に自己ベストを更新した時刻 (秒)。同点なら早く到達した人が上。
	LastAt int64 `json:"lastAt"`
}

// summarizeContest は競技の得点をプレイヤーごとに集計し、順位順に並べる。
func summarizeContest(players []string, c *store.Contest, bests []store.Best) []*contestEntry {
	byPlayer := map[string]*contestEntry{}
	for _, name := range players {
		byPlayer[name] = &contestEntry{Player: name, Scores: map[string]store.Best{}}
	}
	for _, b := range bests {
		e, ok := byPlayer[b.Player]
		if !ok || !c.Includes(b.ScenarioID) {
			continue
		}
		e.Scores[b.ScenarioID] = b
		e.Total += b.Score
		if b.Score >= scenario.MasteryScore {
			e.Solved++
		}
		e.LastAt = max(e.LastAt, b.UpdatedAt)
	}
	entries := make([]*contestEntry, 0, len(byPlayer))
	for _, e := range byPlayer {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		x, y := entries[i], entries[j]
		if x.Total != y.Total {
			return x.Total > y.Total
		}
		if x.Total > 0 && x.LastAt != y.LastAt {
			return x.LastAt < y.LastAt
		}
		return x.Player < y.Player
	})
	return entries
}

// contestState は今の競技とランキングを返す。競技がなければ contest は null。
func (a *app) contestState(ctx context.Context) (response, error) {
	c, err := a.store.GetContest(ctx)
	if err != nil {
		return response{}, err
	}
	now := time.Now()
	out := struct {
		Contest     *contestView    `json:"contest"`
		Now         int64           `json:"now"`
		Leaderboard []*contestEntry `json:"leaderboard"`
	}{Contest: viewContest(c, now), Now: now.UnixMilli(), Leaderboard: []*contestEntry{}}
	if c != nil {
		bests, err := a.store.ListContestBest(ctx, c.ID)
		if err != nil {
			return response{}, err
		}
		out.Leaderboard = summarizeContest(a.players, c, bests)
	}
	return jsonResponse(http.StatusOK, out), nil
}

// contestable は競技で出題できる問題か (チュートリアル以外。CloudFront を作っていなければ CloudFront の問題を除く)。
func (a *app) contestable(sc *scenario.Scenario) bool {
	return !sc.Tutorial && (sc.Target != scenario.TargetCloudFront || a.cloudFront)
}

func (a *app) adminContest(ctx context.Context, req events.LambdaFunctionURLRequest, method, path string, lang scenario.Lang) (response, error) {
	if !a.isAdmin(req) {
		return errorResponse(http.StatusForbidden, lang, "adminOnly"), nil
	}
	now := time.Now()
	var in struct {
		Title     string   `json:"title"`
		Scenarios []string `json:"scenarios"`
		// Minutes は今から何分後に終了するか。0 なら時間制限なし。
		Minutes int `json:"minutes"`
	}
	if method == http.MethodPut || method == http.MethodPatch {
		body, err := requestBody(req)
		if err != nil || json.Unmarshal([]byte(body), &in) != nil || in.Minutes < 0 || in.Minutes > maxContestMinutes {
			return errorResponse(http.StatusBadRequest, lang, "badBody"), nil
		}
	}
	endsAt := func() int64 {
		if in.Minutes == 0 {
			return 0
		}
		return now.Add(time.Duration(in.Minutes) * time.Minute).UnixMilli()
	}

	switch {
	case method == http.MethodPut && path == "/api/admin/contest":
		var ids []string
		for _, id := range in.Scenarios {
			sc, ok := scenario.Get(id)
			if !ok || !a.contestable(sc) {
				return errorResponse(http.StatusBadRequest, lang, "badContest"), nil
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 || len([]rune(in.Title)) > 60 {
			return errorResponse(http.StatusBadRequest, lang, "badContest"), nil
		}
		c := &store.Contest{ID: newID(), Title: in.Title, Scenarios: ids, StartedAt: now.UnixMilli(), EndsAt: endsAt()}
		if err := a.store.PutContest(ctx, c); err != nil {
			return response{}, err
		}
		return a.contestState(ctx)
	case method == http.MethodDelete && path == "/api/admin/contest":
		if err := a.store.DeleteContest(ctx); err != nil {
			return response{}, err
		}
		return a.contestState(ctx)
	}

	// 以下は開いている競技の変更
	c, err := a.store.GetContest(ctx)
	if err != nil {
		return response{}, err
	}
	if c == nil {
		return errorResponse(http.StatusNotFound, lang, "noContest"), nil
	}
	switch {
	case method == http.MethodPatch && path == "/api/admin/contest":
		// 延長や再開にも使えるよう、終了済みでも新しい終了時刻で続ける
		c.EndsAt, c.EndedAt = endsAt(), 0
	case method == http.MethodPost && path == "/api/admin/contest/end":
		if c.EndedAt == 0 {
			c.EndedAt = now.UnixMilli()
		}
	default:
		return errorResponse(http.StatusNotFound, lang, "notFound"), nil
	}
	if err := a.store.PutContest(ctx, c); err != nil {
		return response{}, err
	}
	return a.contestState(ctx)
}

// requestBody は Function URL のリクエストの Body を返す (base64 なら戻す)。
func requestBody(req events.LambdaFunctionURLRequest) (string, error) {
	if !req.IsBase64Encoded {
		return req.Body, nil
	}
	b, err := base64.StdEncoding.DecodeString(req.Body)
	return string(b), err
}
