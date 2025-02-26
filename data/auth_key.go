package data

import (
	"context"
	"fmt"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthKey struct {
	Ecosystem string `dynamodbav:"Ecosystem"`
	KeyID     string `dynamodbav:"KeyID"`

	EncryptedData EncryptedData[*proto.AuthKeyData] `dynamodbav:"EncryptedData"`
}

func (k *AuthKey) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Ecosystem": &types.AttributeValueMemberS{Value: k.Ecosystem},
		"KeyID":     &types.AttributeValueMemberS{Value: k.KeyID},
	}
}

func (k *AuthKey) CorrespondsTo(data *proto.AuthKeyData) bool {
	if k.Ecosystem != data.Ecosystem {
		return false
	}
	expectedKey := &proto.AuthKey{
		PublicKey: data.PublicKey,
		KeyType:   data.KeyType,
	}
	if k.KeyID != expectedKey.String() {
		return false
	}
	return true
}

type AuthKeyIndices struct{}

type AuthKeyTable struct {
	db       DB
	tableARN string
	indices  AuthKeyIndices
}

func NewAuthKeyTable(db DB, tableARN string, indices AuthKeyIndices) *AuthKeyTable {
	return &AuthKeyTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

func (t *AuthKeyTable) Get(ctx context.Context, ecosystem string, keyID string) (*AuthKey, bool, error) {
	authKey := AuthKey{Ecosystem: ecosystem, KeyID: keyID}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       authKey.Key(),
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &authKey); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &authKey, true, nil
}

func (t *AuthKeyTable) Put(ctx context.Context, key *AuthKey) error {
	av, err := attributevalue.MarshalMap(key)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: &t.tableARN,
		Item:      av,
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("PutItem: %w", err)
	}
	return nil
}
