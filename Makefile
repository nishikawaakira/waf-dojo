FUNCS := targetapp trafficgen gameapi
TF := terraform -chdir=terraform

.PHONY: build test dev deploy destroy clean players admin reset-rules reset-scores

build:
	@for f in $(FUNCS); do \
		echo "build $$f"; \
		GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -trimpath -ldflags="-s -w" -o build/$$f/bootstrap ./cmd/$$f || exit 1; \
	done

test:
	go vet ./...
	go test ./...

# Local server to try the game screens without AWS (http://127.0.0.1:8080)
dev:
	WAFDY_DEV=1 go run ./cmd/gameapi

deploy: test build
	$(TF) init -input=false
	$(TF) apply

# Print what to hand out to each player (game URL, console user name and password)
players:
	@terraform -chdir=terraform output -json player_access | python3 tools/print_players.py

# Print the URL of the admin page (start and end contests)
admin:
	@terraform -chdir=terraform output -raw admin_url; echo

# Empty a player's Web ACL rules / delete their score records (e.g. make reset-rules PLAYER=player1)
reset-rules:
	@tools/reset_player.sh rules $(PLAYER)

reset-scores:
	@tools/reset_player.sh scores $(PLAYER)

destroy:
	$(TF) destroy

clean:
	rm -rf build
