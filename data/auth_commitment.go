package data

import (
	"context"
	"fmt"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthID proto.AuthID

func (id *AuthID) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberS{Value: proto.AuthID(*id).String()}, nil
}

func (id *AuthID) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid auth session ID of type: %T", value)
	}
	return (*proto.AuthID)(id).FromString(v.Value)
}

type AuthCommitment struct {
	ID AuthID `dynamodbav:"ID"`

	EncryptedData[*proto.AuthCommitmentData]
}

func (c *AuthCommitment) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ID": &types.AttributeValueMemberS{Value: proto.AuthID(c.ID).String()},
	}
}

func (c *AuthCommitment) CorrespondsTo(data *proto.AuthCommitmentData) bool {
	if c == nil || data == nil {
		return false
	}
	if c.ID.AuthMode != data.AuthMode {
		return false
	}
	if c.ID.IdentityType != data.IdentityType {
		return false
	}
	if c.ID.Verifier != data.Handle && c.ID.Verifier != data.Signer {
		return false
	}
	if c.ID.Ecosystem != data.Ecosystem {
		return false
	}
	return true
}

type AuthCommitmentIndices struct{}

type AuthCommitmentTable struct {
	db       DB
	tableARN string
	indices  AuthCommitmentIndices
}

func NewAuthCommitmentTable(db DB, tableARN string, indices AuthCommitmentIndices) *AuthCommitmentTable {
	return &AuthCommitmentTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

func (t *AuthCommitmentTable) Get(ctx context.Context, authID proto.AuthID) (*AuthCommitment, bool, error) {
	commitment := AuthCommitment{ID: AuthID(authID)}

	out, err := t.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       commitment.Key(),
	})
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
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
	av, err := attributevalue.MarshalMap(commitment)
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
			"attribute_exists(ID) AND EncryptionKeyRef = :key_ref AND Ciphertext = :ciphertext",
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":key_ref":    &types.AttributeValueMemberS{Value: oldData.EncryptionKeyRef},
			":ciphertext": &types.AttributeValueMemberS{Value: oldData.Ciphertext},
		},
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("PutItem: %w", err)
	}
	return nil
}
