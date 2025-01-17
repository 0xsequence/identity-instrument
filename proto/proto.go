// Server
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=nitro.ridl -target=golang -pkg=proto -server -client -out=./nitro.gen.go

// Clients
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=nitro.ridl -target=golang -pkg=proto -client -out=./clients/nitro.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=nitro.ridl -target=typescript -client -out=./clients/nitro.gen.ts

package proto
