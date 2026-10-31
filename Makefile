FUNCS := targetapp trafficgen gameapi
TF := terraform -chdir=terraform

.PHONY: build test dev deploy destroy clean players reset-rules reset-scores

build:
	@for f in $(FUNCS); do \
		echo "build $$f"; \
		GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -trimpath -ldflags="-s -w" -o build/$$f/bootstrap ./cmd/$$f || exit 1; \
	done

test:
	go vet ./...
	go test ./...

# AWS なしで画面を確かめるローカルサーバー (http://127.0.0.1:8080)
dev:
	WAFDY_DEV=1 go run ./cmd/gameapi

deploy: test build
	$(TF) init -input=false
	$(TF) apply

# 各プレイヤーに配る情報 (ゲーム URL・コンソールの ID とパスワード) を表示する
players:
	@terraform -chdir=terraform output -json player_access | python3 tools/print_players.py

# プレイヤーの Web ACL のルールを空に戻す / スコアの記録を消す (例: make reset-rules PLAYER=player1)
reset-rules:
	@tools/reset_player.sh rules $(PLAYER)

reset-scores:
	@tools/reset_player.sh scores $(PLAYER)

destroy:
	$(TF) destroy

clean:
	rm -rf build
