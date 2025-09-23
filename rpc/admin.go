package rpc

import (
	"context"
	"fmt"

	"github.com/0xsequence/identity-instrument/data"
	protoadmin "github.com/0xsequence/identity-instrument/proto/admin"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
)

func (s *RPC) RotateCipherKey(ctx context.Context, keyRef string) error {
	att := attestation.FromContext(ctx)
	return s.EncryptionPool.RotateKey(ctx, att, keyRef)
}

func (s *RPC) RefreshEncryptedData(ctx context.Context, table protoadmin.Table, keyRef string, batch int) (bool, error) {
	switch table {
	case protoadmin.Table_Signers:
		return refreshEncryptedData[*data.Signer](ctx, s, s.Signers.EncryptedDataTable, keyRef, batch)
	case protoadmin.Table_AuthKeys:
		return refreshEncryptedData[*data.AuthKey](ctx, s, s.AuthKeys.EncryptedDataTable, keyRef, batch)
	case protoadmin.Table_AuthCommitments:
		return refreshEncryptedData[*data.AuthCommitment](ctx, s, s.AuthCommitments.EncryptedDataTable, keyRef, batch)
	}
	return false, fmt.Errorf("invalid table: %s", table)
}

func refreshEncryptedData[T data.Record](ctx context.Context, s *RPC, table data.EncryptedDataTable[T], keyRef string, batch int) (bool, error) {
	att := attestation.FromContext(ctx)

	records, done, err := table.ListByCipherKeyRef(ctx, keyRef, batch)
	if err != nil {
		return false, err
	}

	for _, record := range records {
		decrypted, err := record.GetEncryptedData().Decrypt(ctx, att, s.EncryptionPool)
		if err != nil {
			return false, err
		}

		encrypted, err := data.Encrypt(ctx, att, s.EncryptionPool, decrypted)
		if err != nil {
			return false, err
		}

		record.SetEncryptedData(encrypted)
		if err := table.UpdateEncryptedData(ctx, record); err != nil {
			return false, err
		}
	}

	return done, nil
}
