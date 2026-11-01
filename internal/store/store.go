// Package store は DynamoDB に実行履歴・ロック・ベストスコアを保存する。
//
// 1 テーブル構成:
//
//	RUN#<id>       / META            実行 1 回分
//	LOCK#<player>  / LOCK            プレイヤーごとの同時実行防止
//	PLAYER#<name>  / STAGE#<id>      ステージごとのベストスコア
//	CONTEST        / CURRENT         開催中 (または終了後に表示中) の競技
//	CONTEST#<id>   / PLAYER#<name>#STAGE#<id>  競技中のベストスコア (練習の記録とは別)
package store

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"wafdy/internal/score"
)

const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"

	runRetention = 30 * 24 * time.Hour
)

type Run struct {
	PK         string `dynamodbav:"pk" json:"-"`
	SK         string `dynamodbav:"sk" json:"-"`
	ID         string `dynamodbav:"id" json:"id"`
	Player     string `dynamodbav:"player" json:"player"`
	ScenarioID string `dynamodbav:"scenarioId" json:"scenarioId"`
	HintUsed   bool   `dynamodbav:"hintUsed" json:"hintUsed"`
	// Recon は採点しない偵察の実行 (運用演習)。
	Recon       bool          `dynamodbav:"recon,omitempty" json:"recon,omitempty"`
	Status      string        `dynamodbav:"status" json:"status"`
	CreatedAt   int64         `dynamodbav:"createdAt" json:"createdAt"`
	StartedAt   int64         `dynamodbav:"startedAt,omitempty" json:"startedAt,omitempty"`
	DurationSec int           `dynamodbav:"durationSec" json:"durationSec"`
	Result      *score.Result `dynamodbav:"result,omitempty" json:"result,omitempty"`
	Error       string        `dynamodbav:"error,omitempty" json:"error,omitempty"`
	TTL         int64         `dynamodbav:"ttl" json:"-"`
}

type Best struct {
	Player     string `dynamodbav:"player" json:"player"`
	ScenarioID string `dynamodbav:"scenarioId" json:"scenarioId"`
	Score      int    `dynamodbav:"score" json:"score"`
	HintUsed   bool   `dynamodbav:"hintUsed" json:"hintUsed"`
	RunID      string `dynamodbav:"runId" json:"runId"`
	UpdatedAt  int64  `dynamodbav:"updatedAt" json:"updatedAt"`
	// Contest は競技の ID。空なら練習の記録。
	Contest string `dynamodbav:"contest,omitempty" json:"-"`
}

// Contest は管理者が開く競技。出題する問題と終了時刻を持つ。
type Contest struct {
	PK        string   `dynamodbav:"pk" json:"-"`
	SK        string   `dynamodbav:"sk" json:"-"`
	ID        string   `dynamodbav:"id" json:"id"`
	Title     string   `dynamodbav:"title" json:"title"`
	Scenarios []string `dynamodbav:"scenarios" json:"scenarios"`
	StartedAt int64    `dynamodbav:"startedAt" json:"startedAt"`
	// EndsAt は終了予定の時刻 (ミリ秒)。0 なら時間制限なし。
	EndsAt int64 `dynamodbav:"endsAt" json:"endsAt"`
	// EndedAt は管理者が終了した時刻 (ミリ秒)。0 ならまだ終了していない。
	EndedAt int64 `dynamodbav:"endedAt" json:"endedAt"`
}

// Running は競技が続いているか (攻撃を開始できるか) を返す。
func (c *Contest) Running(now time.Time) bool {
	return c.EndedAt == 0 && (c.EndsAt == 0 || now.UnixMilli() < c.EndsAt)
}

// Includes はその問題が出題されているかを返す。
func (c *Contest) Includes(scenarioID string) bool {
	for _, id := range c.Scenarios {
		if id == scenarioID {
			return true
		}
	}
	return false
}

var ErrLocked = errors.New("another run is in progress")

type Store struct {
	db    *dynamodb.Client
	table string
}

func New(ctx context.Context) (*Store, error) {
	table := os.Getenv("TABLE_NAME")
	if table == "" {
		return nil, errors.New("TABLE_NAME is not set")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &Store{db: dynamodb.NewFromConfig(cfg), table: table}, nil
}

func runKey(id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: "RUN#" + id},
		"sk": &types.AttributeValueMemberS{Value: "META"},
	}
}

func lockKey(player string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: "LOCK#" + player},
		"sk": &types.AttributeValueMemberS{Value: "LOCK"},
	}
}

func num(n int64) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

func str(s string) *types.AttributeValueMemberS { return &types.AttributeValueMemberS{Value: s} }

func isConditionFailed(err error) bool {
	var ccf *types.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}

func (s *Store) CreateRun(ctx context.Context, run *Run) error {
	run.PK, run.SK = "RUN#"+run.ID, "META"
	run.TTL = time.Now().Add(runRetention).Unix()
	item, err := attributevalue.MarshalMap(run)
	if err != nil {
		return err
	}
	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.table, Item: item})
	return err
}

// GetRun は見つからなければ nil を返す。
func (s *Store) GetRun(ctx context.Context, id string) (*Run, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.table, Key: runKey(id), ConsistentRead: aws.Bool(true)})
	if err != nil || out.Item == nil {
		return nil, err
	}
	var run Run
	if err := attributevalue.UnmarshalMap(out.Item, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

func (s *Store) MarkRunning(ctx context.Context, id string, startedAt time.Time) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.table,
		Key:                       runKey(id),
		UpdateExpression:          aws.String("SET #status = :s, #startedAt = :t"),
		ExpressionAttributeNames:  map[string]string{"#status": "status", "#startedAt": "startedAt"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":s": str(StatusRunning), ":t": num(startedAt.UnixMilli())},
	})
	return err
}

func (s *Store) FinishRun(ctx context.Context, id string, res *score.Result, runErr error) error {
	names := map[string]string{"#status": "status"}
	values := map[string]types.AttributeValue{}
	expr := "SET #status = :s"
	if runErr != nil {
		values[":s"] = str(StatusFailed)
		values[":e"] = str(runErr.Error())
		names["#error"] = "error"
		expr += ", #error = :e"
	} else {
		av, err := attributevalue.Marshal(res)
		if err != nil {
			return err
		}
		values[":s"] = str(StatusDone)
		values[":r"] = av
		names["#result"] = "result"
		expr += ", #result = :r"
	}
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.table,
		Key:                       runKey(id),
		UpdateExpression:          &expr,
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	return err
}

// AcquireLock はプレイヤーの環境で同時に 1 つしか実行しないようにする。
// 期限切れのロックは奪える。
func (s *Store) AcquireLock(ctx context.Context, player, runID string, ttl time.Duration) error {
	now := time.Now()
	item := lockKey(player)
	item["runId"] = str(runID)
	item["expiresAt"] = num(now.Add(ttl).Unix())
	item["ttl"] = num(now.Add(ttl + time.Hour).Unix())
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 &s.table,
		Item:                      item,
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR expiresAt < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": num(now.Unix())},
	})
	if isConditionFailed(err) {
		return ErrLocked
	}
	return err
}

// ReleaseLock は自分が取ったロックだけを外す。
func (s *Store) ReleaseLock(ctx context.Context, player, runID string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.table,
		Key:                       lockKey(player),
		ConditionExpression:       aws.String("runId = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": str(runID)},
	})
	if isConditionFailed(err) {
		return nil
	}
	return err
}

func bestKey(b Best) map[string]types.AttributeValue {
	if b.Contest != "" {
		return map[string]types.AttributeValue{
			"pk": str("CONTEST#" + b.Contest),
			"sk": str("PLAYER#" + b.Player + "#STAGE#" + b.ScenarioID),
		}
	}
	return map[string]types.AttributeValue{
		"pk": str("PLAYER#" + b.Player),
		"sk": str("STAGE#" + b.ScenarioID),
	}
}

// RecordBest はスコアが自己ベストを上回ったときだけ保存する。b.Contest があれば、その競技の記録として保存する。
func (s *Store) RecordBest(ctx context.Context, b Best) error {
	b.UpdatedAt = time.Now().Unix()
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           &s.table,
		Key:                 bestKey(b),
		UpdateExpression:    aws.String("SET #player = :p, #scenarioId = :sc, #score = :s, #hintUsed = :h, #runId = :r, #updatedAt = :u"),
		ConditionExpression: aws.String("attribute_not_exists(pk) OR #score < :s"),
		ExpressionAttributeNames: map[string]string{
			"#player": "player", "#scenarioId": "scenarioId", "#score": "score",
			"#hintUsed": "hintUsed", "#runId": "runId", "#updatedAt": "updatedAt",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": str(b.Player), ":sc": str(b.ScenarioID), ":s": num(int64(b.Score)),
			":h": &types.AttributeValueMemberBOOL{Value: b.HintUsed}, ":r": str(b.RunID), ":u": num(b.UpdatedAt),
		},
	})
	if isConditionFailed(err) {
		return nil
	}
	return err
}

func (s *Store) GetBest(ctx context.Context, player, scenarioID string) (*Best, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.table,
		Key:       bestKey(Best{Player: player, ScenarioID: scenarioID}),
	})
	if err != nil || out.Item == nil {
		return nil, err
	}
	var b Best
	return &b, attributevalue.UnmarshalMap(out.Item, &b)
}

// ListBest は全プレイヤーのベストスコアを返す。学習環境の規模なら Scan で十分。
func (s *Store) ListBest(ctx context.Context) ([]Best, error) {
	var bests []Best
	p := dynamodb.NewScanPaginator(s.db, &dynamodb.ScanInput{
		TableName:                 &s.table,
		FilterExpression:          aws.String("begins_with(pk, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": str("PLAYER#")},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var items []Best
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &items); err != nil {
			return nil, err
		}
		bests = append(bests, items...)
	}
	return bests, nil
}

// ListContestBest は競技中の全プレイヤーのベストスコアを返す。
func (s *Store) ListContestBest(ctx context.Context, contestID string) ([]Best, error) {
	var bests []Best
	p := dynamodb.NewQueryPaginator(s.db, &dynamodb.QueryInput{
		TableName:                 &s.table,
		KeyConditionExpression:    aws.String("pk = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": str("CONTEST#" + contestID)},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		var items []Best
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &items); err != nil {
			return nil, err
		}
		bests = append(bests, items...)
	}
	return bests, nil
}

func contestKey() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"pk": str("CONTEST"), "sk": str("CURRENT")}
}

// GetContest は今の競技を返す。競技がなければ (通常モード) nil。
func (s *Store) GetContest(ctx context.Context) (*Contest, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.table, Key: contestKey(), ConsistentRead: aws.Bool(true)})
	if err != nil || out.Item == nil {
		return nil, err
	}
	var c Contest
	return &c, attributevalue.UnmarshalMap(out.Item, &c)
}

func (s *Store) PutContest(ctx context.Context, c *Contest) error {
	c.PK, c.SK = "CONTEST", "CURRENT"
	item, err := attributevalue.MarshalMap(c)
	if err != nil {
		return err
	}
	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.table, Item: item})
	return err
}

// DeleteContest は通常モードに戻す。競技の記録 (CONTEST#<id>) は残す。
func (s *Store) DeleteContest(ctx context.Context) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.table, Key: contestKey()})
	return err
}
