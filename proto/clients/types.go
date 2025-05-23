package proto

import "fmt"

type Scope string

func (k *Key) String() string {
	return fmt.Sprintf("%s:%s", k.KeyType, k.Address)
}
