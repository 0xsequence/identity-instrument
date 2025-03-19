package data

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type EncryptionPoolKey struct {
	// Generation is a sequence number of the encryption config used to encrypt the shares of this key.
	Generation int `dynamodbav:"Generation"`
	// KeyIndex is the index of the key within the config version.
	KeyIndex int `dynamodbav:"KeyIndex"`
	// KeyRef uniquely identifies the private key material.
	KeyRef string `dynamodbav:"KeyRef"`

	EncryptedShares map[string]string `dynamodbav:"EncryptedShares"`

	Attestation []byte `dynamodbav:"Attestation"`
}

func (k *EncryptionPoolKey) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Generation": &types.AttributeValueMemberN{Value: strconv.Itoa(k.Generation)},
		"KeyIndex":   &types.AttributeValueMemberN{Value: strconv.Itoa(k.KeyIndex)},
	}
}

type EncryptionPoolKeyIndices struct {
	KeyRefIndex string
}

type EncryptionPoolKeyTable struct {
	db       DB
	tableARN string
	indices  EncryptionPoolKeyIndices
}

func NewEncryptionPoolKeyTable(db DB, tableARN string, indices EncryptionPoolKeyIndices) *EncryptionPoolKeyTable {
	return &EncryptionPoolKeyTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

func (t *EncryptionPoolKeyTable) Get(ctx context.Context, generation int, keyIndex int, consistentRead bool) (*EncryptionPoolKey, bool, error) {
	key := EncryptionPoolKey{Generation: generation, KeyIndex: keyIndex}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &t.tableARN,
		Key:            key.Key(),
		ConsistentRead: &consistentRead,
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &key); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &key, true, nil
}

func (t *EncryptionPoolKeyTable) GetLatestByKeyRef(ctx context.Context, keyRef string, consistentRead bool) (*EncryptionPoolKey, bool, error) {
	var key EncryptionPoolKey
	out, err := t.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.KeyRefIndex,
		KeyConditionExpression: aws.String("KeyRef = :keyRef"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":keyRef": &types.AttributeValueMemberS{Value: keyRef},
		},
		ScanIndexForward: aws.Bool(false), // return the key with highest Generation
		Limit:            aws.Int32(1),
		ConsistentRead:   &consistentRead,
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Items) == 0 || len(out.Items[0]) == 0 {
		return nil, false, nil
	}
	if err := attributevalue.UnmarshalMap(out.Items[0], &key); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &key, true, nil
}

func (t *EncryptionPoolKeyTable) Create(ctx context.Context, key *EncryptionPoolKey) (alreadyExists bool, err error) {
	av, err := attributevalue.MarshalMap(key)
	if err != nil {
		return false, fmt.Errorf("marshal input: %w", err)
	}
	_, err = t.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &t.tableARN,
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(Generation) AND attribute_not_exists(KeyIndex)"),
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return true, nil
		}
		return false, fmt.Errorf("PutItem: %w", err)
	}
	return false, nil
}
