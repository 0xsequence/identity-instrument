package data

import (
	"context"
	"fmt"
	"strings"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type ScopedKeyType struct {
	Scope   proto.Scope
	KeyType proto.KeyType
}

func (s ScopedKeyType) Encode() (string, error) {
	if !s.Scope.IsValid() || strings.Contains(string(s.Scope), "/") {
		return "", fmt.Errorf("invalid scope: %s", s.Scope)
	}
	if strings.Contains(string(s.KeyType), "/") {
		return "", fmt.Errorf("invalid key type: %s", s.KeyType)
	}
	return fmt.Sprintf("%s/%s", s.Scope, s.KeyType), nil
}

func (s ScopedKeyType) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	encoded, err := s.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return &types.AttributeValueMemberS{Value: encoded}, nil
}

func (s *ScopedKeyType) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid scoped key type of type: %T", value)
	}
	parts := strings.Split(v.Value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid scoped key type: %s", v.Value)
	}
	s.Scope = proto.Scope(parts[0])
	s.KeyType = proto.KeyType(parts[1])
	return nil
}

type Signer struct {
	Address       string        `dynamodbav:"Address"`
	IdentityHash  string        `dynamodbav:"IdentityHash"`
	ScopedKeyType ScopedKeyType `dynamodbav:"ScopedKeyType"`

	Identity *proto.Identity `dynamodbav:"-"`

	EncryptedData[*proto.SignerData]
}

func (s *Signer) Key() proto.Key {
	return proto.Key{
		KeyType: s.ScopedKeyType.KeyType,
		Address: s.Address,
	}
}

func (s *Signer) DatabaseKey() (map[string]types.AttributeValue, error) {
	scopedKeyType, err := s.ScopedKeyType.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode scoped key type: %w", err)
	}
	return map[string]types.AttributeValue{
		"IdentityHash":  &types.AttributeValueMemberS{Value: s.IdentityHash},
		"ScopedKeyType": &types.AttributeValueMemberS{Value: scopedKeyType},
	}, nil
}

func (s *Signer) GetEncryptedData() EncryptedData[any] {
	return s.EncryptedData.ToAny()
}

func (s *Signer) SetEncryptedData(data EncryptedData[any]) {
	s.EncryptedData = EncryptedData[*proto.SignerData](data)
}

func (s *Signer) CorrespondsToData(data *proto.SignerData, cryptoKey any) bool {
	if s.ScopedKeyType.Scope != data.Scope {
		return false
	}
	if s.ScopedKeyType.KeyType != data.KeyType {
		return false
	}
	identHash, err := data.Identity.Hash()
	if err != nil {
		return false
	}
	if s.IdentityHash != identHash {
		return false
	}
	key, err := proto.NewKeyFromPrivateKey(data.KeyType, cryptoKey)
	if err != nil {
		return false
	}
	if s.Address != key.Address {
		return false
	}
	if key.KeyType != data.KeyType {
		return false
	}
	return true
}

func (s *Signer) CorrespondsToProtoKey(protoKey proto.Key) bool {
	if s.ScopedKeyType.KeyType != protoKey.KeyType {
		return false
	}
	if s.Address != protoKey.Address {
		return false
	}
	return true
}

type SignerIndices struct {
	ByAddress      string
	ByCipherKeyRef string
}

type SignerTable struct {
	db       DB
	tableARN string
	indices  SignerIndices
	EncryptedDataTable[*Signer]
}

func NewSignerTable(db DB, tableARN string, indices SignerIndices) *SignerTable {
	return &SignerTable{
		db:                 db,
		tableARN:           tableARN,
		indices:            indices,
		EncryptedDataTable: NewEncryptedDataTable[*Signer](db, tableARN, indices.ByCipherKeyRef),
	}
}

func (t *SignerTable) TableARN() string {
	return t.tableARN
}

func (t *SignerTable) GetByIdentity(ctx context.Context, ident proto.Identity, scope proto.Scope, keyType proto.KeyType) (*Signer, bool, error) {
	identHash, err := ident.Hash()
	if err != nil {
		return nil, false, fmt.Errorf("hash identity: %w", err)
	}
	signer := Signer{
		IdentityHash:  identHash,
		ScopedKeyType: ScopedKeyType{Scope: scope, KeyType: keyType},
	}
	dbKey, err := signer.DatabaseKey()
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

	if err := attributevalue.UnmarshalMap(out.Item, &signer); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &signer, true, nil
}

func (t *SignerTable) GetByAddress(ctx context.Context, scope proto.Scope, key proto.Key) (*Signer, bool, error) {
	var signer Signer
	scopedKeyType, err := ScopedKeyType{
		Scope:   scope,
		KeyType: key.KeyType,
	}.Encode()
	if err != nil {
		return nil, false, fmt.Errorf("encode scoped key type: %w", err)
	}
	out, err := t.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.ByAddress,
		KeyConditionExpression: aws.String("Address = :address and ScopedKeyType = :scopedKeyType"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":address":       &types.AttributeValueMemberS{Value: strings.ToLower(key.Address)},
			":scopedKeyType": &types.AttributeValueMemberS{Value: scopedKeyType},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return nil, false, fmt.Errorf("query: %w", err)
	}
	if len(out.Items) == 0 || len(out.Items[0]) == 0 {
		return nil, false, nil
	}
	if err := attributevalue.UnmarshalMap(out.Items[0], &signer); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &signer, true, nil
}

func (t *SignerTable) Put(ctx context.Context, signer *Signer) (err error) {
	if signer.Identity == nil {
		return fmt.Errorf("identity is required")
	}

	signer.Address = strings.ToLower(signer.Address)
	signer.IdentityHash, err = signer.Identity.Hash()
	if err != nil {
		return fmt.Errorf("hash identity: %w", err)
	}

	av, err := attributevalue.MarshalMap(signer)
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
