package data

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Encryptor interface {
	Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (keyID string, ciphertext string, err error)
}

type Decryptor interface {
	Decrypt(ctx context.Context, att *enclave.Attestation, keyID string, ciphertext string) ([]byte, error)
}

type EncryptedData[T any] struct {
	// CipherKeyRef is the reference to the cipher key used to encrypt the data.
	CipherKeyRef string `dynamodbav:"CipherKeyRef"`
	// Ciphertext is the encrypted data.
	Ciphertext string `dynamodbav:"Ciphertext"`
	// CiphertextHash is the hash of the ciphertext, to be used as a unique identifier for the data.
	CiphertextHash []byte `dynamodbav:"CiphertextHash"`
}

func Encrypt[T any](ctx context.Context, att *enclave.Attestation, encryptor Encryptor, data T) (EncryptedData[T], error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return EncryptedData[T]{}, fmt.Errorf("marshal data: %w", err)
	}

	keyID, ciphertext, err := encryptor.Encrypt(ctx, att, plaintext)
	if err != nil {
		return EncryptedData[T]{}, err
	}

	hash := sha256.Sum256([]byte(ciphertext))

	ed := EncryptedData[T]{
		CipherKeyRef:   keyID,
		Ciphertext:     ciphertext,
		CiphertextHash: hash[:],
	}
	return ed, nil
}

func (ed EncryptedData[T]) Decrypt(ctx context.Context, att *enclave.Attestation, decryptor Decryptor) (T, error) {
	var zero T

	plaintext, err := decryptor.Decrypt(ctx, att, ed.CipherKeyRef, ed.Ciphertext)
	if err != nil {
		return zero, err
	}

	var out T
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return zero, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, nil
}

func (ed EncryptedData[T]) ToAny() EncryptedData[any] {
	return EncryptedData[any](ed)
}

// EncryptedDataTable defines methods common to all tables that store encrypted data.
// It is not meant to be used directly, but rather to be embedded in a concrete table type.
type EncryptedDataTable[T Record] struct {
	db                DB
	tableARN          string
	cipherKeyRefIndex string
}

func NewEncryptedDataTable[T Record](db DB, tableARN string, cipherKeyRefIndex string) EncryptedDataTable[T] {
	return EncryptedDataTable[T]{
		db:                db,
		tableARN:          tableARN,
		cipherKeyRefIndex: cipherKeyRefIndex,
	}
}

// ReferencesCipherKeyRef checks if the table contains any records that are encrypted with the given cipher key.
func (t *EncryptedDataTable[T]) ReferencesCipherKeyRef(ctx context.Context, keyRef string) (bool, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.cipherKeyRefIndex,
		KeyConditionExpression: aws.String("CipherKeyRef = :keyRef"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":keyRef": &types.AttributeValueMemberS{Value: keyRef},
		},
		Select: types.SelectCount,
		Limit:  aws.Int32(1),
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return false, fmt.Errorf("query: %w", err)
	}
	return out.Count > 0, nil
}

// ListByCipherKeyRef lists records in the table that are encrypted with the given cipher key. It only returns
// the first page of results and a boolean indicating if there are more results that were not returned.
func (t *EncryptedDataTable[T]) ListByCipherKeyRef(ctx context.Context, keyRef string, pageSize int) ([]T, bool, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.cipherKeyRefIndex,
		KeyConditionExpression: aws.String("CipherKeyRef = :keyRef"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":keyRef": &types.AttributeValueMemberS{Value: keyRef},
		},
		Limit: aws.Int32(int32(pageSize)),
	}
	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("query: %w", err)
	}

	var records []T
	for _, item := range out.Items {
		// Create a properly initialized record
		var record T
		recordType := reflect.TypeOf(record)
		if recordType.Kind() == reflect.Ptr {
			// T is a pointer type, create a new instance of the underlying type
			elemType := recordType.Elem()
			newElem := reflect.New(elemType)
			record = newElem.Interface().(T)
		}

		if err := attributevalue.UnmarshalMap(item, &record); err != nil {
			return nil, false, fmt.Errorf("unmarshal result: %w", err)
		}
		records = append(records, record)
	}
	return records, len(out.LastEvaluatedKey) == 0, nil
}

// UpdateEncryptedData updates the encrypted data for a record in the table.
func (t *EncryptedDataTable[T]) UpdateEncryptedData(ctx context.Context, record T) error {
	ed := record.GetEncryptedData()
	dbKey, err := record.DatabaseKey()
	if err != nil {
		return fmt.Errorf("encode database key: %w", err)
	}
	input := &dynamodb.UpdateItemInput{
		TableName:        &t.tableARN,
		Key:              dbKey,
		UpdateExpression: aws.String("SET CipherKeyRef = :cipherKeyRef, Ciphertext = :ciphertext, CiphertextHash = :ciphertextHash"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":cipherKeyRef":   &types.AttributeValueMemberS{Value: ed.CipherKeyRef},
			":ciphertext":     &types.AttributeValueMemberS{Value: ed.Ciphertext},
			":ciphertextHash": &types.AttributeValueMemberB{Value: ed.CiphertextHash},
		},
	}
	if _, err := t.db.UpdateItem(ctx, input); err != nil {
		return fmt.Errorf("update item: %w", err)
	}
	return nil
}
