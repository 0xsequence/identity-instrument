package data

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/fxamacker/cbor/v2"
)

type CipherKey struct {
	// Generation is a sequence number of the encryption config used to encrypt the shares of this key.
	Generation int `dynamodbav:"Generation" cbor:"0,keyasint"`
	// KeyIndex is the index of the key within the config version.
	KeyIndex *int `dynamodbav:"KeyIndex,omitempty" cbor:"1,keyasint"`
	// KeyRef uniquely identifies the private key material.
	KeyRef string `dynamodbav:"KeyRef" cbor:"2,keyasint"`

	// EncryptedShares is a map of remote key references to encrypted share values.
	EncryptedShares map[string]string `dynamodbav:"EncryptedShares" cbor:"3,keyasint"`

	// Attestation is the Nitro attestation document with the CipherKey's Hash as UserData.
	Attestation []byte `dynamodbav:"Attestation" cbor:"-"`

	CreatedAt     time.Time  `dynamodbav:"CreatedAt" cbor:"4,keyasint"`
	InactiveSince *time.Time `dynamodbav:"InactiveSince,omitempty" cbor:"5,keyasint,omitempty"`
}

func (k *CipherKey) DatabaseKey() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"KeyRef":     &types.AttributeValueMemberS{Value: k.KeyRef},
		"Generation": &types.AttributeValueMemberN{Value: strconv.Itoa(k.Generation)},
	}
}

func (k *CipherKey) Hash() ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical encoder: %w", err)
	}
	b, err := enc.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("marshal hash payload: %w", err)
	}

	h := sha256.New()
	h.Write(b)
	return h.Sum(nil), nil
}

type CipherKeyIndices struct {
	ByKeyIndexAndGeneration string
	Inactive                string
}

type CipherKeyTable struct {
	db       DB
	tableARN string
	indices  CipherKeyIndices
}

func NewCipherKeyTable(db DB, tableARN string, indices CipherKeyIndices) *CipherKeyTable {
	return &CipherKeyTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

func (t *CipherKeyTable) TableARN() string {
	return t.tableARN
}

func (t *CipherKeyTable) Get(ctx context.Context, generation int, keyIndex int) (*CipherKey, bool, error) {
	var key CipherKey
	out, err := t.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.ByKeyIndexAndGeneration,
		KeyConditionExpression: aws.String("Generation = :generation AND KeyIndex = :keyIndex"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":generation": &types.AttributeValueMemberN{Value: strconv.Itoa(generation)},
			":keyIndex":   &types.AttributeValueMemberN{Value: strconv.Itoa(keyIndex)},
		},
		Limit: aws.Int32(1),
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

func (t *CipherKeyTable) GetLatestByKeyRef(ctx context.Context, keyRef string, consistentRead bool) (*CipherKey, bool, error) {
	var key CipherKey
	out, err := t.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &t.tableARN,
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

func (t *CipherKeyTable) Create(ctx context.Context, key *CipherKey) (alreadyExists bool, err error) {
	av, err := attributevalue.MarshalMap(key)
	if err != nil {
		return false, fmt.Errorf("marshal input: %w", err)
	}
	_, err = t.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &t.tableARN,
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(KeyRef) AND attribute_not_exists(Generation)"),
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

func (t *CipherKeyTable) ScanInactive(ctx context.Context, cursor *string) ([]*CipherKey, *string, error) {
	var keys []*CipherKey

	var startKey map[string]types.AttributeValue
	if cursor != nil {
		if err := json.Unmarshal([]byte(*cursor), &startKey); err != nil {
			return nil, nil, fmt.Errorf("unmarshal cursor: %w", err)
		}
	}

	out, err := t.db.Scan(ctx, &dynamodb.ScanInput{
		TableName:         &t.tableARN,
		IndexName:         &t.indices.Inactive,
		ExclusiveStartKey: startKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Scan: %w", err)
	}

	if len(out.Items) > 0 {
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &keys); err != nil {
			return nil, nil, fmt.Errorf("unmarshal query results: %w", err)
		}
	}

	var nextCursor *string
	if len(out.LastEvaluatedKey) > 0 {
		b, err := json.Marshal(out.LastEvaluatedKey)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal last evaluated key: %w", err)
		}
		s := string(b)
		nextCursor = &s
	}

	return keys, nextCursor, nil
}

func (t *CipherKeyTable) Delete(ctx context.Context, keyRef string, generation int) error {
	key := CipherKey{Generation: generation, KeyRef: keyRef}
	_, err := t.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &t.tableARN,
		Key:       key.DatabaseKey(),
	})
	if err != nil {
		return fmt.Errorf("DeleteItem: %w", err)
	}
	return nil
}

func (t *CipherKeyTable) Deactivate(ctx context.Context, keyRef string, generation int, now time.Time, attestation []byte) error {
	key := CipherKey{Generation: generation, KeyRef: keyRef}
	_, err := t.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &t.tableARN,
		Key:              key.DatabaseKey(),
		UpdateExpression: aws.String("SET Attestation = :attestation, InactiveSince = :inactiveSince REMOVE KeyIndex"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":attestation":   &types.AttributeValueMemberB{Value: attestation},
			":inactiveSince": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339Nano)},
		},
	})
	if err != nil {
		return fmt.Errorf("UpdateItem: %w", err)
	}
	return nil
}
