package proto

func (c *AuthCommitmentData) Verifier() string {
	if c.Signer.IsValid() {
		return c.Signer.String()
	}
	return c.Handle
}
