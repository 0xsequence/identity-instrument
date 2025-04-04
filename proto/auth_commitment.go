package proto

func (c *AuthCommitmentData) Verifier() string {
	if c.Signer != "" {
		return c.Signer
	}
	return c.Handle
}
