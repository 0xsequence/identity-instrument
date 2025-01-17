package proto

func (k AuthKey) String() string {
	return string(k.KeyType) + ":" + k.PublicKey
}
