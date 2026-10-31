package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestHandlesALBAndFunctionURLEvents(t *testing.T) {
	alb := `{"requestContext":{"elb":{"targetGroupArn":"arn"}},"httpMethod":"GET","path":"/Admin/x"}`
	res, err := handler(context.Background(), json.RawMessage(alb))
	if r, ok := res.(events.ALBTargetGroupResponse); err != nil || !ok || r.StatusCode != 200 || r.Body != `{"page":"admin","shop":"WAF Dojo demo shop"}` {
		t.Fatalf("ALB: %#v, %v", res, err)
	}
	url := `{"rawPath":"/api/reports","requestContext":{"http":{"method":"POST"}},"body":"x"}`
	res, err = handler(context.Background(), json.RawMessage(url))
	if r, ok := res.(events.LambdaFunctionURLResponse); err != nil || !ok || r.StatusCode != 200 || r.Body != `{"page":"reports","shop":"WAF Dojo demo shop"}` {
		t.Fatalf("Function URL: %#v, %v", res, err)
	}
}
