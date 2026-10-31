package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"wafdy/internal/scenario"
	"wafdy/internal/store"
)

func TestMessagesAreTranslated(t *testing.T) {
	for key, msg := range messages {
		for _, l := range scenario.Langs {
			if msg[l] == "" {
				t.Errorf("message %q: missing %q translation", key, l)
			}
		}
	}
}

func TestLangOf(t *testing.T) {
	req := func(query, accept string) events.LambdaFunctionURLRequest {
		return events.LambdaFunctionURLRequest{
			QueryStringParameters: map[string]string{"lang": query},
			Headers:               map[string]string{"accept-language": accept},
		}
	}
	cases := []struct {
		query, accept string
		want          scenario.Lang
	}{
		{"ja", "en-US", scenario.Japanese},        // ?lang= が優先
		{"", "ja-JP,ja;q=0.9", scenario.Japanese}, // Accept-Language
		{"fr", "de-DE", scenario.English},         // どちらも未対応なら英語
	}
	for _, c := range cases {
		if got := langOf(req(c.query, c.accept)); got != c.want {
			t.Errorf("langOf(%q, %q) = %q, want %q", c.query, c.accept, got, c.want)
		}
	}
}

func TestSummarizeSpecialist(t *testing.T) {
	var bests []store.Best
	add := func(player string, list []*scenario.Scenario, score int) {
		for _, s := range list {
			bests = append(bests, store.Best{Player: player, ScenarioID: s.ID, Score: score})
		}
	}
	add("master", scenario.Tutorials(), 100)
	add("master", scenario.Games(), scenario.MasteryScore)
	add("master", scenario.Labs(), 100)
	add("master", scenario.Exams(), 100)
	add("master", scenario.OpsDrills(), 100)
	add("almost", scenario.Tutorials(), 100)
	add("almost", scenario.Games(), 100)
	add("almost", scenario.Labs(), 100)
	add("almost", scenario.Exams()[1:], 100)
	add("almost", scenario.Exams()[:1], scenario.MasteryScore-1)
	add("almost", scenario.OpsDrills(), 100)

	entries := summarize([]string{"almost", "master", "newbie"}, bests)
	got := map[string]*leaderboardEntry{}
	for _, e := range entries {
		got[e.Player] = e
	}
	if !got["master"].Specialist {
		t.Error("master should be a specialist")
	}
	if got["almost"].Specialist {
		t.Error("almost has one exam below the mastery score and should not be a specialist")
	}
	if got["master"].Mastered[scenario.CategoryLab] != len(scenario.Labs()) || got["almost"].Mastered[scenario.CategoryExam] != len(scenario.Exams())-1 {
		t.Errorf("mastered = %v / %v", got["master"].Mastered, got["almost"].Mastered)
	}
	if got["newbie"].Total != 0 || entries[len(entries)-1].Player != "newbie" {
		t.Error("newbie should be last with 0 points")
	}
}

func TestActingPlayerRequiresOwnToken(t *testing.T) {
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	a := &app{players: []string{"player1", "player2"}, tokenHashes: map[string]string{"player1": hash("tok-1"), "player2": hash("tok-2")}}
	req := func(token string) events.LambdaFunctionURLRequest {
		return events.LambdaFunctionURLRequest{Headers: map[string]string{"x-wafdy-token": token}}
	}
	// 自分のトークンなら、リクエストで別のプレイヤーを名乗っても自分として扱う
	if p, ok := a.actingPlayer(req("tok-1"), "player2"); !ok || p != "player1" {
		t.Errorf("token of player1 acted as %q, %v", p, ok)
	}
	if _, ok := a.actingPlayer(req("wrong"), "player1"); ok {
		t.Error("a wrong token must not act as anyone")
	}
	if _, ok := a.actingPlayer(req(""), "player1"); ok {
		t.Error("no token must not act as anyone when tokens are required")
	}
	// トークンを設定していない (一人で遊ぶ・開発モード) なら、名前だけで遊べる
	open := &app{players: []string{"player1"}}
	if p, ok := open.actingPlayer(req(""), "player1"); !ok || p != "player1" {
		t.Errorf("without tokens, got %q, %v", p, ok)
	}
}

func TestServeStaticEncodesBinaryFiles(t *testing.T) {
	png := serveStatic("/apple-touch-icon.png")
	if png.StatusCode != 200 || !png.IsBase64Encoded {
		t.Fatalf("png: status %d, base64 %v", png.StatusCode, png.IsBase64Encoded)
	}
	raw, err := base64.StdEncoding.DecodeString(png.Body)
	if err != nil || !bytes.HasPrefix(raw, []byte("\x89PNG")) {
		t.Fatalf("png body is not a valid base64 PNG: %v", err)
	}
	for _, p := range []string{"/", "/app.js", "/style.css", "/favicon.svg"} {
		if r := serveStatic(p); r.StatusCode != 200 || r.IsBase64Encoded {
			t.Errorf("%s: status %d, base64 %v (text should be served as-is)", p, r.StatusCode, r.IsBase64Encoded)
		}
	}
}
