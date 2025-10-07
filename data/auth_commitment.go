package data

import (
	"context"
	"fmt"
	"time"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthCommitment struct {
	ID        string    `dynamodbav:"ID"`
	ExpiresAt time.Time `dynamodbav:"ExpiresAt,unixtime"`

	AuthID *proto.AuthID `dynamodbav:"-"`

	EncryptedData[*proto.AuthCommitmentData]
}

func (c *AuthCommitment) DatabaseKey() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ID": &types.AttributeValueMemberS{Value: c.ID},
	}
}

func (c *AuthCommitment) GetEncryptedData() EncryptedData[any] {
	return c.ToAny()
}

func (c *AuthCommitment) SetEncryptedData(data EncryptedData[any]) {
	c.EncryptedData = EncryptedData[*proto.AuthCommitmentData](data)
}

func (c *AuthCommitment) CorrespondsTo(data *proto.AuthCommitmentData) bool {
	if c == nil || data == nil {
		return false
	}
	handleAuthID := proto.AuthID{
		AuthMode:     data.AuthMode,
		IdentityType: data.IdentityType,
		Verifier:     data.Handle,
		Scope:        data.Scope,
	}
	signerAuthID := proto.AuthID{
		AuthMode:     data.AuthMode,
		IdentityType: data.IdentityType,
		Verifier:     data.Signer.String(),
		Scope:        data.Scope,
	}
	if c.AuthID != nil && *c.AuthID != handleAuthID && *c.AuthID != signerAuthID {
		return false
	} else if c.ID != "" && c.ID != handleAuthID.Hash() && c.ID != signerAuthID.Hash() {
		return false
	}
	if c.ExpiresAt.Unix() != data.Expiry.Unix() {
		return false
	}
	return true
}

type AuthCommitmentIndices struct {
	ByCipherKeyRef string
}

type AuthCommitmentTable struct {
	db       DB
	tableARN string
	indices  AuthCommitmentIndices
	EncryptedDataTable[*AuthCommitment]
}

func NewAuthCommitmentTable(db DB, tableARN string, indices AuthCommitmentIndices) *AuthCommitmentTable {
	return &AuthCommitmentTable{
		db:                 db,
		tableARN:           tableARN,
		indices:            indices,
		EncryptedDataTable: NewEncryptedDataTable[*AuthCommitment](db, tableARN, indices.ByCipherKeyRef),
	}
}

func (t *AuthCommitmentTable) TableARN() string {
	return t.tableARN
}

func (t *AuthCommitmentTable) Get(ctx context.Context, authID proto.AuthID) (*AuthCommitment, bool, error) {
	commitment := AuthCommitment{ID: authID.Hash()}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       commitment.DatabaseKey(),
	})
	if err != nil {
		return nil, false, fmt.Errorf("get item: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &commitment); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &commitment, true, nil
}

func (t *AuthCommitmentTable) Put(ctx context.Context, commitment *AuthCommitment) error {
	commitment.ID = commitment.AuthID.Hash()

	av, err := attributevalue.MarshalMap(commitment)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: &t.tableARN,
		Item:      av,
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("put item: %w", err)
	}
	return nil
}

func (t *AuthCommitmentTable) UpdateData(
	ctx context.Context, current *AuthCommitment, data EncryptedData[*proto.AuthCommitmentData],
) error {
	oldData := current.EncryptedData
	current.EncryptedData = data

	av, err := attributevalue.MarshalMap(current)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: &t.tableARN,
		Item:      av,
		ConditionExpression: aws.String(
			"attribute_exists(ID) AND CipherKeyRef = :key_ref AND Ciphertext = :ciphertext",
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":key_ref":    &types.AttributeValueMemberS{Value: oldData.CipherKeyRef},
			":ciphertext": &types.AttributeValueMemberS{Value: oldData.Ciphertext},
		},
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("put item: %w", err)
	}
	return nil
}
