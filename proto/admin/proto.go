// Server
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=admin.ridl -target=golang -pkg=proto -server -client -out=./admin.gen.go

package proto
