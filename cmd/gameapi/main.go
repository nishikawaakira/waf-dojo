// gameapi は Lambda Function URL で公開するゲーム画面と API。
//
//	GET  /                    画面 (web/ を埋め込み配信)
//	GET  /api/config          プレイヤー一覧・リージョン・シナリオ一覧
//	GET  /api/scenarios/{id}  シナリオの説明（攻撃の事前情報）
//	POST /api/runs            攻撃開始
//	GET  /api/runs/{id}       実行状況と結果
//	GET  /api/leaderboard     ランキング
//
// 競技モードの API は contest.go。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"wafdy/internal/scenario"
	"wafdy/internal/score"
	"wafdy/internal/store"
)

//go:embed web
var webFS embed.FS

// gameStore は app が使う保存先。本番は DynamoDB (store.Store)、開発モードはメモリ上。
type gameStore interface {
	GetRun(ctx context.Context, id string) (*store.Run, error)
	CreateRun(ctx context.Context, run *store.Run) error
	FinishRun(ctx context.Context, id string, res *score.Result, runErr error) error
	AcquireLock(ctx context.Context, player, runID string, ttl time.Duration) error
	ReleaseLock(ctx context.Context, player, runID string) error
	GetBest(ctx context.Context, player, scenarioID string) (*store.Best, error)
	ListBest(ctx context.Context) ([]store.Best, error)
	ListContestBest(ctx context.Context, contestID string) ([]store.Best, error)
	GetContest(ctx context.Context) (*store.Contest, error)
	PutContest(ctx context.Context, c *store.Contest) error
	DeleteContest(ctx context.Context) error
}

// functionInvoker はトラフィック生成 Lambda の呼び出し。
type functionInvoker interface {
	Invoke(ctx context.Context, in *awslambda.InvokeInput, optFns ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error)
}

type app struct {
	store      gameStore
	lambda     functionInvoker
	trafficgen string
	players    []string
	region     string
	project    string
	passcode   string
	// cloudFront は、プレイヤーごとの CloudFront と CloudFront 用の Web ACL を作ってあるか。
	cloudFront bool
	// tokenHashes はプレイヤーごとのトークンの SHA-256 (16 進)。空ならトークンなしで誰でもどのプレイヤーとしても遊べる。
	tokenHashes map[string]string
	// adminHash は管理者のトークンの SHA-256 (16 進)。競技の開始・終了に使う。
	adminHash string
}

// playerFromToken は X-Wafdy-Token ヘッダーのトークンに対応するプレイヤーを返す。
func (a *app) playerFromToken(req events.LambdaFunctionURLRequest) (string, bool) {
	token := req.Headers["x-wafdy-token"]
	if token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	for player, want := range a.tokenHashes {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return player, true
		}
	}
	return "", false
}

// actingPlayer は操作するプレイヤーを決める。トークンが必要な設定なら、トークンのプレイヤーだけを許す。
func (a *app) actingPlayer(req events.LambdaFunctionURLRequest, requested string) (string, bool) {
	if len(a.tokenHashes) == 0 {
		return requested, slices.Contains(a.players, requested)
	}
	return a.playerFromToken(req)
}

type response = events.LambdaFunctionURLResponse

func jsonResponse(status int, v any) response {
	body, _ := json.Marshal(v)
	return response{StatusCode: status, Headers: map[string]string{"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}, Body: string(body)}
}

// API のエラーメッセージ。画面にそのまま表示する。
var messages = map[string]scenario.Text{
	"passcode":        scenario.T("パスコードが必要です", "A passcode is required"),
	"noScenario":      scenario.T("シナリオが見つかりません", "Scenario not found"),
	"noRun":           scenario.T("実行が見つかりません", "Run not found"),
	"noPlayer":        scenario.T("プレイヤーが見つかりません", "Player not found"),
	"badBody":         scenario.T("リクエストの形式が正しくありません", "Invalid request body"),
	"tutorialFirst":   scenario.T("先にすべてのチュートリアルをクリアしてください", "Clear all the tutorials first"),
	"busy":            scenario.T("このプレイヤーの環境では別の攻撃が実行中です", "Another attack is already running in this player's environment"),
	"notFound":        scenario.T("見つかりません", "Not found"),
	"noCloudFront":    scenario.T("この環境では CloudFront を使う問題は遊べません (管理者が enable_cloudfront を無効にしています)", "CloudFront problems aren't available in this environment (the administrator disabled enable_cloudfront)"),
	"tokenRequired":   scenario.T("プレイするには、自分専用の URL から開いてください", "Open the game from your own personal URL to play"),
	"noSolution":      scenario.T("この問題の模範解答は公開されていません", "This problem has no published model answer"),
	"solutionLocked":  scenario.T("模範解答は一度挑戦すると見られます", "The model answer unlocks after your first attempt"),
	"adminOnly":       scenario.T("管理者用の URL から開いてください", "Open this from the administrator URL"),
	"badContest":      scenario.T("出題する問題を 1 つ以上選んでください (競技名は 60 文字まで)", "Choose at least one problem (the contest name can be up to 60 characters)"),
	"noContest":       scenario.T("開催中の競技はありません", "No contest is open"),
	"notInContest":    scenario.T("この問題は今回の競技では出題されていません", "This problem isn't part of the current contest"),
	"contestEnded":    scenario.T("競技は終了しました", "The contest has ended"),
	"contestSolution": scenario.T("模範解答は競技の終了後に見られます", "Model answers are available after the contest ends"),
}

func errorResponse(status int, lang scenario.Lang, key string) response {
	return jsonResponse(status, map[string]string{"error": messages[key].In(lang)})
}

// langOf は ?lang= を優先し、なければ Accept-Language から言語を決める。どちらもなければ英語。
func langOf(req events.LambdaFunctionURLRequest) scenario.Lang {
	if l, ok := scenario.ParseLang(req.QueryStringParameters["lang"]); ok {
		return l
	}
	if l, ok := scenario.LangFromAcceptLanguage(req.Headers["accept-language"]); ok {
		return l
	}
	return scenario.English
}

func (a *app) handle(ctx context.Context, req events.LambdaFunctionURLRequest) (response, error) {
	method := req.RequestContext.HTTP.Method
	p := req.RawPath
	lang := langOf(req)

	if !strings.HasPrefix(p, "/api/") {
		return serveStatic(p), nil
	}
	if a.passcode != "" && subtle.ConstantTimeCompare([]byte(req.Headers["x-wafdy-passcode"]), []byte(a.passcode)) != 1 {
		return errorResponse(http.StatusUnauthorized, lang, "passcode"), nil
	}

	switch {
	case method == http.MethodGet && p == "/api/config":
		return a.config(ctx, req, lang)
	case method == http.MethodGet && strings.HasPrefix(p, "/api/scenarios/") && strings.HasSuffix(p, "/solution"):
		player, ok := a.actingPlayer(req, req.QueryStringParameters["player"])
		if !ok {
			return errorResponse(http.StatusUnauthorized, lang, "tokenRequired"), nil
		}
		return a.solution(ctx, strings.TrimSuffix(strings.TrimPrefix(p, "/api/scenarios/"), "/solution"), player, lang)
	case method == http.MethodGet && strings.HasPrefix(p, "/api/scenarios/"):
		sc, ok := scenario.Get(strings.TrimPrefix(p, "/api/scenarios/"))
		if !ok {
			return errorResponse(http.StatusNotFound, lang, "noScenario"), nil
		}
		return jsonResponse(http.StatusOK, sc.View(lang)), nil
	case method == http.MethodPost && p == "/api/runs":
		return a.startRun(ctx, req, lang)
	case method == http.MethodGet && strings.HasPrefix(p, "/api/runs/"):
		run, err := a.store.GetRun(ctx, strings.TrimPrefix(p, "/api/runs/"))
		if err != nil {
			return response{}, err
		}
		if run == nil {
			return errorResponse(http.StatusNotFound, lang, "noRun"), nil
		}
		return jsonResponse(http.StatusOK, run), nil
	case method == http.MethodGet && p == "/api/leaderboard":
		return a.leaderboard(ctx)
	case method == http.MethodGet && p == "/api/contest":
		return a.contestState(ctx)
	case strings.HasPrefix(p, "/api/admin/contest"):
		return a.adminContest(ctx, req, method, p, lang)
	}
	return errorResponse(http.StatusNotFound, lang, "notFound"), nil
}

func serveStatic(p string) response {
	if p == "/" || p == "" {
		p = "/index.html"
	}
	data, err := webFS.ReadFile("web" + path.Clean(p))
	if err != nil {
		return response{StatusCode: http.StatusNotFound, Body: "not found"}
	}
	contentType := mime.TypeByExtension(path.Ext(p))
	res := response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": contentType, "Cache-Control": "no-cache"},
		Body:       string(data),
	}
	// 画像などのバイナリは、Function URL の決まりで base64 にして返す
	if !strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "svg") {
		res.Body = base64.StdEncoding.EncodeToString(data)
		res.IsBase64Encoded = true
	}
	return res
}

func (a *app) config(ctx context.Context, req events.LambdaFunctionURLRequest, lang scenario.Lang) (response, error) {
	type player struct {
		Name   string `json:"name"`
		WebACL string `json:"webAcl"`
		// CFWebACL は CloudFront に付いている Web ACL (CloudFront を使う問題で設定する)。
		CFWebACL string `json:"cfWebAcl,omitempty"`
	}
	type summary struct {
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Summary  string   `json:"summary"`
		Topics   []string `json:"topics"`
		Tutorial bool     `json:"tutorial"`
		Category string   `json:"category"`
		Level    int      `json:"level,omitempty"`
		CVE      string   `json:"cve,omitempty"`
		Target   string   `json:"target,omitempty"`
	}
	cfg := struct {
		Lang               scenario.Lang   `json:"lang"`
		Langs              []scenario.Lang `json:"langs"`
		Region             string          `json:"region"`
		Players            []player        `json:"players"`
		Scenarios          []summary       `json:"scenarios"`
		TutorialClearScore int             `json:"tutorialClearScore"`
		MasteryScore       int             `json:"masteryScore"`
		RequireToken       bool            `json:"requireToken"`
		Me                 string          `json:"me,omitempty"`
		// Admin は管理者のトークンで開いているか。
		Admin bool `json:"admin"`
		// Contest は開催中 (または終了後に表示中) の競技。なければ通常モード。
		Contest *contestView `json:"contest"`
		// Now はサーバーの時刻 (ミリ秒)。画面の残り時間を、端末の時計のずれに左右されずに出すため。
		Now int64 `json:"now"`
	}{Admin: a.isAdmin(req), RequireToken: len(a.tokenHashes) > 0, Lang: lang, Langs: scenario.Langs, Region: a.region, TutorialClearScore: scenario.TutorialClearScore, MasteryScore: scenario.MasteryScore}
	for _, name := range a.players {
		p := player{Name: name, WebACL: a.project + "-" + name}
		if a.cloudFront {
			p.CFWebACL = a.project + "-" + name + "-cf"
		}
		cfg.Players = append(cfg.Players, p)
	}
	if me, ok := a.playerFromToken(req); ok {
		cfg.Me = me
	}
	for _, s := range scenario.All() {
		v := s.View(lang)
		cfg.Scenarios = append(cfg.Scenarios, summary{v.ID, v.Title, v.Summary, v.Topics, v.Tutorial, v.Category, v.Level, v.CVE, v.Target})
	}
	contest, err := a.store.GetContest(ctx)
	if err != nil {
		return response{}, err
	}
	now := time.Now()
	cfg.Contest, cfg.Now = viewContest(contest, now), now.UnixMilli()
	return jsonResponse(http.StatusOK, cfg), nil
}

func (a *app) startRun(ctx context.Context, req events.LambdaFunctionURLRequest, lang scenario.Lang) (response, error) {
	body, err := requestBody(req)
	if err != nil {
		return errorResponse(http.StatusBadRequest, lang, "badBody"), nil
	}
	var in struct {
		Player     string `json:"player"`
		ScenarioID string `json:"scenarioId"`
		HintUsed   bool   `json:"hintUsed"`
		Recon      bool   `json:"recon"`
	}
	if err := json.Unmarshal([]byte(body), &in); err != nil {
		return errorResponse(http.StatusBadRequest, lang, "badBody"), nil
	}
	player, ok := a.actingPlayer(req, in.Player)
	if !ok {
		if len(a.tokenHashes) > 0 {
			return errorResponse(http.StatusUnauthorized, lang, "tokenRequired"), nil
		}
		return errorResponse(http.StatusBadRequest, lang, "noPlayer"), nil
	}
	in.Player = player
	sc, ok := scenario.Get(in.ScenarioID)
	if !ok {
		return errorResponse(http.StatusBadRequest, lang, "noScenario"), nil
	}
	// 競技中は、出題された問題だけを、チュートリアルなしで解ける
	contest, err := a.store.GetContest(ctx)
	if err != nil {
		return response{}, err
	}
	contestID := ""
	if contest != nil {
		if !contest.Includes(sc.ID) {
			return errorResponse(http.StatusForbidden, lang, "notInContest"), nil
		}
		if !contest.Running(time.Now()) {
			return errorResponse(http.StatusForbidden, lang, "contestEnded"), nil
		}
		contestID = contest.ID
	} else if !sc.Tutorial {
		cleared, err := a.tutorialsCleared(ctx, in.Player)
		if err != nil {
			return response{}, err
		}
		if !cleared {
			return errorResponse(http.StatusForbidden, lang, "tutorialFirst"), nil
		}
	}

	if sc.Target == scenario.TargetCloudFront && !a.cloudFront {
		return errorResponse(http.StatusBadRequest, lang, "noCloudFront"), nil
	}

	id := newID()
	if err := a.store.AcquireLock(ctx, in.Player, id, sc.Duration+2*time.Minute); err != nil {
		if errors.Is(err, store.ErrLocked) {
			return errorResponse(http.StatusConflict, lang, "busy"), nil
		}
		return response{}, err
	}
	run := &store.Run{
		ID:          id,
		Player:      in.Player,
		ScenarioID:  sc.ID,
		HintUsed:    in.HintUsed && !sc.Tutorial,
		Recon:       in.Recon && sc.Recon,
		Status:      store.StatusQueued,
		CreatedAt:   time.Now().UnixMilli(),
		DurationSec: int(sc.Duration.Seconds()),
	}
	if err := a.store.CreateRun(ctx, run); err != nil {
		_ = a.store.ReleaseLock(ctx, in.Player, id)
		return response{}, err
	}
	payload, _ := json.Marshal(map[string]any{"runId": id, "player": run.Player, "scenarioId": run.ScenarioID, "hintUsed": run.HintUsed, "recon": run.Recon, "contestId": contestID})
	_, err = a.lambda.Invoke(ctx, &awslambda.InvokeInput{
		FunctionName:   &a.trafficgen,
		InvocationType: lambdatypes.InvocationTypeEvent,
		Payload:        payload,
	})
	if err != nil {
		_ = a.store.FinishRun(ctx, id, nil, err)
		_ = a.store.ReleaseLock(ctx, in.Player, id)
		return response{}, err
	}
	return jsonResponse(http.StatusAccepted, run), nil
}

// tutorialsCleared はすべてのチュートリアルでクリア点を取ったかを返す。
func (a *app) tutorialsCleared(ctx context.Context, player string) (bool, error) {
	for _, t := range scenario.Tutorials() {
		best, err := a.store.GetBest(ctx, player, t.ID)
		if err != nil {
			return false, err
		}
		if best == nil || best.Score < scenario.TutorialClearScore {
			return false, nil
		}
	}
	return true, nil
}

// solution は模範解答を返す。答えを見てから挑戦できないよう、一度挑戦したプレイヤーにだけ返す。
// 競技中はどの問題も見られず、競技が終わると出題された問題は挑戦していなくても見られる。
func (a *app) solution(ctx context.Context, id, player string, lang scenario.Lang) (response, error) {
	sc, ok := scenario.Get(id)
	if !ok || sc.SolutionView(lang) == nil {
		return errorResponse(http.StatusNotFound, lang, "noSolution"), nil
	}
	contest, err := a.store.GetContest(ctx)
	if err != nil {
		return response{}, err
	}
	if contest != nil {
		if contest.Running(time.Now()) {
			return errorResponse(http.StatusForbidden, lang, "contestSolution"), nil
		}
		if contest.Includes(id) {
			return jsonResponse(http.StatusOK, sc.SolutionView(lang)), nil
		}
	}
	best, err := a.store.GetBest(ctx, player, id)
	if err != nil {
		return response{}, err
	}
	if best == nil {
		return errorResponse(http.StatusForbidden, lang, "solutionLocked"), nil
	}
	return jsonResponse(http.StatusOK, sc.SolutionView(lang)), nil
}

type leaderboardEntry struct {
	Player string `json:"player"`
	// Total はチュートリアル以外のベストスコアの合計。
	Total            int `json:"total"`
	TutorialsCleared int `json:"tutorialsCleared"`
	// Mastered はカテゴリ (game / lab / exam / ops) ごとの、MasteryScore 以上の問題の数。
	Mastered   map[string]int        `json:"mastered"`
	Specialist bool                  `json:"specialist"`
	Stages     map[string]store.Best `json:"stages"`
}

// summarize はベストスコアをプレイヤーごとに集計し、順位順に並べる。
// チュートリアルをすべてクリアし、ゲームとラボをすべて MasteryScore 以上にすると WAF スペシャリスト。
func summarize(players []string, bests []store.Best) []*leaderboardEntry {
	byPlayer := map[string]*leaderboardEntry{}
	for _, name := range players {
		byPlayer[name] = &leaderboardEntry{Player: name, Stages: map[string]store.Best{}, Mastered: map[string]int{}}
	}
	for _, b := range bests {
		e, ok := byPlayer[b.Player]
		if !ok {
			continue // 削除されたプレイヤー
		}
		sc, ok := scenario.Get(b.ScenarioID)
		if !ok {
			continue // 削除されたシナリオ
		}
		e.Stages[b.ScenarioID] = b
		if sc.Tutorial {
			if b.Score >= scenario.TutorialClearScore {
				e.TutorialsCleared++
			}
			continue
		}
		e.Total += b.Score
		if b.Score >= scenario.MasteryScore {
			e.Mastered[sc.Category()]++
		}
	}
	entries := make([]*leaderboardEntry, 0, len(byPlayer))
	for _, e := range byPlayer {
		mastered := 0
		for _, n := range e.Mastered {
			mastered += n
		}
		e.Specialist = e.TutorialsCleared == len(scenario.Tutorials()) && mastered == len(scenario.Masterable())
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Total != entries[j].Total {
			return entries[i].Total > entries[j].Total
		}
		if entries[i].TutorialsCleared != entries[j].TutorialsCleared {
			return entries[i].TutorialsCleared > entries[j].TutorialsCleared
		}
		return entries[i].Player < entries[j].Player
	})
	return entries
}

func (a *app) leaderboard(ctx context.Context) (response, error) {
	bests, err := a.store.ListBest(ctx)
	if err != nil {
		return response{}, err
	}
	return jsonResponse(http.StatusOK, summarize(a.players, bests)), nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	if os.Getenv("WAFDY_DEV") != "" {
		runDev(os.Getenv("WAFDY_DEV_ADDR"))
		return
	}
	ctx := context.Background()
	st, err := store.New(ctx)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	a := &app{
		store:      st,
		lambda:     awslambda.NewFromConfig(cfg),
		trafficgen: os.Getenv("TRAFFICGEN_FUNCTION"),
		region:     cfg.Region,
		project:    os.Getenv("PROJECT"),
		passcode:   os.Getenv("GAME_PASSCODE"),
		cloudFront: os.Getenv("CLOUDFRONT_ENABLED") == "true",
		adminHash:  os.Getenv("ADMIN_TOKEN_HASH"),
	}
	if err := json.Unmarshal([]byte(os.Getenv("PLAYERS")), &a.players); err != nil || len(a.players) == 0 {
		log.Fatal("PLAYERS must be a non-empty JSON array")
	}
	if v := os.Getenv("PLAYER_TOKEN_HASHES"); v != "" {
		if err := json.Unmarshal([]byte(v), &a.tokenHashes); err != nil {
			log.Fatal("PLAYER_TOKEN_HASHES must be a JSON object of player -> sha256 hex")
		}
	}
	lambda.Start(a.handle)
}
