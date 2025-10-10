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

type AuthKey struct {
	KeyHash   string      `dynamodbav:"KeyHash"`
	Scope     proto.Scope `dynamodbav:"Scope"`
	ExpiresAt time.Time   `dynamodbav:"ExpiresAt,unixtime"`

	Key *proto.Key `dynamodbav:"-"`

	UsageWindowStart   time.Time `dynamodbav:"UsageWindowStart"`
	UsageCountInWindow int       `dynamodbav:"UsageCountInWindow"`

	EncryptedData[*proto.AuthKeyData]
}

func (k *AuthKey) DatabaseKey() (map[string]types.AttributeValue, error) {
	return map[string]types.AttributeValue{
		"Scope":   &types.AttributeValueMemberS{Value: k.Scope.String()},
		"KeyHash": &types.AttributeValueMemberS{Value: k.KeyHash},
	}, nil
}

func (k *AuthKey) GetEncryptedData() EncryptedData[any] {
	return k.EncryptedData.ToAny()
}

func (k *AuthKey) SetEncryptedData(data EncryptedData[any]) {
	k.EncryptedData = EncryptedData[*proto.AuthKeyData](data)
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
	dbKey, err := authKey.DatabaseKey()
	if err != nil {
		return nil, false, fmt.Errorf("encode database key: %w", err)
	}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       dbKey,
	})
	if err != nil {
		return nil, false, fmt.Errorf("get item: %w", err)
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
		return fmt.Errorf("put item: %w", err)
	}
	return nil
}

func (t *AuthKeyTable) ResetUsageWindow(ctx context.Context, key *AuthKey, windowStart time.Time) error {
	dbKey, err := key.DatabaseKey()
	if err != nil {
		return fmt.Errorf("encode database key: %w", err)
	}
	input := &dynamodb.UpdateItemInput{
		TableName:        &t.tableARN,
		Key:              dbKey,
		UpdateExpression: aws.String("SET UsageCountInWindow = :initialCount, UsageWindowStart = :windowStart"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":windowStart":  &types.AttributeValueMemberS{Value: windowStart.Format(time.RFC3339Nano)},
			":initialCount": &types.AttributeValueMemberN{Value: "1"},
		},
	}
	if _, err := t.db.UpdateItem(ctx, input); err != nil {
		return fmt.Errorf("UpdateItem: %w", err)
	}
	return nil
}

func (t *AuthKeyTable) IncrementUsageCount(ctx context.Context, key *AuthKey) error {
	dbKey, err := key.DatabaseKey()
	if err != nil {
		return fmt.Errorf("encode database key: %w", err)
	}
	input := &dynamodb.UpdateItemInput{
		TableName:           &t.tableARN,
		Key:                 dbKey,
		UpdateExpression:    aws.String("ADD UsageCountInWindow :increment"),
		ConditionExpression: aws.String("UsageWindowStart = :windowStart"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":windowStart": &types.AttributeValueMemberS{Value: key.UsageWindowStart.Format(time.RFC3339Nano)},
			":increment":   &types.AttributeValueMemberN{Value: "1"},
		},
	}
	if _, err := t.db.UpdateItem(ctx, input); err != nil {
		return fmt.Errorf("UpdateItem: %w", err)
	}
	return nil
}
