FROM golang:alpine AS build
RUN apk add --no-cache clang llvm
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./...
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags "-s -w" -o /filetop-reporter ./cmd/filetop-reporter

FROM scratch
COPY --from=build /filetop-reporter /filetop-reporter
ENTRYPOINT ["/filetop-reporter"]
CMD ["run"]
