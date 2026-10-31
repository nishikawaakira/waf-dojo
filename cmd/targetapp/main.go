// targetapp は学習用の EC サイト（ダミー）。ALB の後ろと、CloudFront の後ろ (Lambda Function URL) の両方で動く。
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

func page(path string) []byte {
	path = strings.ToLower(path)
	var name string
	switch {
	case path == "/":
		name = "top"
	case strings.HasPrefix(path, "/search"):
		name = "search"
	case strings.HasPrefix(path, "/products/"):
		name = "product"
	case strings.HasPrefix(path, "/comment"):
		name = "comment"
	case strings.HasPrefix(path, "/download"):
		name = "download"
	case strings.HasPrefix(path, "/admin"):
		name = "admin"
	case strings.HasPrefix(path, "/login"):
		name = "login"
	case strings.HasPrefix(path, "/api/reports"):
		name = "reports"
	default:
		name = "other"
	}
	body, _ := json.Marshal(map[string]string{"shop": "WAF Dojo demo shop", "page": name})
	return body
}

// handler は ALB と Lambda Function URL のどちらのイベントも受け付ける。
func handler(_ context.Context, raw json.RawMessage) (any, error) {
	var probe struct {
		RequestContext struct {
			ELB *json.RawMessage `json:"elb"`
		} `json:"requestContext"`
	}
	_ = json.Unmarshal(raw, &probe)

	if probe.RequestContext.ELB != nil {
		var req events.ALBTargetGroupRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return events.ALBTargetGroupResponse{
			StatusCode:        200,
			StatusDescription: "200 OK",
			Headers:           map[string]string{"Content-Type": "application/json"},
			Body:              string(page(req.Path)),
		}, nil
	}

	var req events.LambdaFunctionURLRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return events.LambdaFunctionURLResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(page(req.RawPath)),
	}, nil
}

func main() {
	lambda.Start(handler)
}
