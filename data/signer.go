package data

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Signer struct {
	Ecosystem string   `dynamodbav:"Ecosystem"`
	Address   string   `dynamodbav:"Address"`
	Identity  Identity `dynamodbav:"Identity"`

	EncryptedData[*proto.SignerData]
}

func (s *Signer) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Ecosystem": &types.AttributeValueMemberS{Value: s.Ecosystem},
		"Identity":  &types.AttributeValueMemberS{Value: s.Identity.String()},
	}
}

func (s *Signer) CorrespondsTo(data *proto.SignerData, key *ecdsa.PrivateKey) bool {
	if s.Ecosystem != data.Ecosystem {
		return false
	}
	if s.Identity.String() != data.Identity.String() {
		return false
	}
	if s.Address != crypto.PubkeyToAddress(key.PublicKey).Hex() {
		return false
	}
	return true
}

type SignerIndices struct {
	ByAddress string
}

type SignerTable struct {
	db       DB
	tableARN string
	indices  SignerIndices
}

func NewSignerTable(db DB, tableARN string, indices SignerIndices) *SignerTable {
	return &SignerTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

func (t *SignerTable) GetByIdentity(ctx context.Context, ecosystem string, ident proto.Identity) (*Signer, bool, error) {
	signer := Signer{Ecosystem: ecosystem, Identity: Identity(ident)}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       signer.Key(),
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &signer); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &signer, true, nil
}

func (t *SignerTable) GetByAddress(ctx context.Context, ecosystem string, address string) (*Signer, bool, error) {
	var signer Signer
	out, err := t.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.ByAddress,
		KeyConditionExpression: aws.String("Address = :address and Ecosystem = :ecosystem"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":address":   &types.AttributeValueMemberS{Value: address},
			":ecosystem": &types.AttributeValueMemberS{Value: ecosystem},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Items) == 0 || len(out.Items[0]) == 0 {
		return nil, false, nil
	}
	if err := attributevalue.UnmarshalMap(out.Items[0], &signer); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &signer, true, nil
}

func (t *SignerTable) Put(ctx context.Context, signer *Signer) error {
	av, err := attributevalue.MarshalMap(signer)
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
