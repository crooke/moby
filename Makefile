.PHONY: dockerd

dockerd:
	go build -mod=mod ./cmd/dockerd
