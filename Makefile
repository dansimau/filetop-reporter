IMAGE ?= filetop-reporter
# NAS is the ssh host of a Synology box used by the nas-* targets. Set it in
# local.mk (gitignored, see local.mk.example) or on the command line.
NAS ?=
NAS_DIR ?= /volume1/docker/filetop-reporter/build
DOCKER_NAS ?= sudo /usr/local/bin/docker

-include local.mk

.PHONY: docker
docker:
	docker build -t $(IMAGE) .

.PHONY: check-nas
check-nas:
	@test -n "$(NAS)" || { echo "NAS is not set; copy local.mk.example to local.mk"; exit 1; }

# Build the image on the NAS itself (no local Docker or BPF toolchain needed).
.PHONY: nas-build
nas-build: check-nas
	rsync -a --delete --exclude .git --exclude local.mk ./ $(NAS):$(NAS_DIR)/
	ssh $(NAS) "$(DOCKER_NAS) build -t $(IMAGE):dev $(NAS_DIR)"

.PHONY: nas-selftest
nas-selftest: check-nas
	ssh $(NAS) "$(DOCKER_NAS) run --rm --privileged --pid=host -v /sys/kernel/debug:/sys/kernel/debug -v /volume1/docker/filetop-reporter/data:/data $(IMAGE):dev selftest"

.PHONY: vet
vet:
	GOOS=linux GOARCH=amd64 go vet ./internal/container

.PHONY: test
test:
	go test ./internal/...
