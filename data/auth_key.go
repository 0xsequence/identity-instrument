package data

import (
	"context"
	"fmt"
	"time"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthKey struct {
	KeyHash   string      `dynamodbav:"KeyHash"`
	Scope     proto.Scope `dynamodbav:"Scope"`
	ExpiresAt time.Time   `dynamodbav:"ExpiresAt,unixtime"`

	Key *proto.Key `dynamodbav:"-"`

	EncryptedData[*proto.AuthKeyData]
}

func (k *AuthKey) DatabaseKey() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Scope":   &types.AttributeValueMemberS{Value: k.Scope.String()},
		"KeyHash": &types.AttributeValueMemberS{Value: k.KeyHash},
	}
}

func (k *AuthKey) GetEncryptedData() EncryptedData[any] {
	return k.EncryptedData.ToAny()
}

func (k *AuthKey) SetEncryptedData(data EncryptedData[any]) {
	k.EncryptedData = EncryptedData[*proto.AuthKeyData]{
		CipherKeyRef:   data.CipherKeyRef,
		Ciphertext:     data.Ciphertext,
		CiphertextHash: data.CiphertextHash,
	}
}

func (k *AuthKey) CorrespondsTo(data *proto.AuthKeyData) bool {
	if k.Scope != data.Scope {
		return false
	}
	if k.KeyHash != data.AuthKey.Hash() {
		return false
	}
	if k.ExpiresAt.Unix() != data.Expiry.Unix() {
		return false
	}
	return true
}

type AuthKeyIndices struct {
	ByCipherKeyRef string
}

type AuthKeyTable struct {
	db       DB
	tableARN string
	indices  AuthKeyIndices
	EncryptedDataTable[*AuthKey]
}

func NewAuthKeyTable(db DB, tableARN string, indices AuthKeyIndices) *AuthKeyTable {
	return &AuthKeyTable{
		db:                 db,
		tableARN:           tableARN,
		indices:            indices,
		EncryptedDataTable: NewEncryptedDataTable[*AuthKey](db, tableARN, indices.ByCipherKeyRef),
	}
}

func (t *AuthKeyTable) TableARN() string {
	return t.tableARN
}

func (t *AuthKeyTable) Get(ctx context.Context, scope proto.Scope, key proto.Key) (*AuthKey, bool, error) {
	authKey := AuthKey{Scope: scope, KeyHash: key.Hash()}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       authKey.DatabaseKey(),
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
	key.KeyHash = key.Key.Hash()

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
