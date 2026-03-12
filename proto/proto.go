// Server
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=./schema/identity-instrument.ridl -target=golang -pkg=proto -server -client -out=./identity-instrument.gen.go

// Clients
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=./schema/identity-instrument.ridl -target=golang -pkg=proto -client -out=./clients/identity-instrument.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=./schema/identity-instrument.ridl -target=typescript -client -out=./clients/identity-instrument.gen.ts

package proto
