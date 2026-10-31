// targetapp は ALB の後ろで動く学習用の EC サイト（ダミー）。
// 実際の処理は何もせず、どのリクエストにも 200 を返す。
// 4xx が返ったら WAF がブロックした、と生成器が判定できるようにするため。
package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(_ context.Context, req events.ALBTargetGroupRequest) (events.ALBTargetGroupResponse, error) {
	path := strings.ToLower(req.Path)
	var page string
	switch {
	case path == "/":
		page = "top"
	case strings.HasPrefix(path, "/search"):
		page = "search"
	case strings.HasPrefix(path, "/products/"):
		page = "product"
	case strings.HasPrefix(path, "/comment"):
		page = "comment"
	case strings.HasPrefix(path, "/download"):
		page = "download"
	case strings.HasPrefix(path, "/admin"):
		page = "admin"
	case strings.HasPrefix(path, "/login"):
		page = "login"
	default:
		page = "other"
	}
	body, _ := json.Marshal(map[string]string{"shop": "WAF Dojo demo shop", "page": page})
	return events.ALBTargetGroupResponse{
		StatusCode:        200,
		StatusDescription: "200 OK",
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              string(body),
	}, nil
}

func main() {
	lambda.Start(handler)
}
