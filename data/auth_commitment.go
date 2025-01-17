package data

import (
	"context"
	"fmt"
	"strings"

	proto "github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthID struct {
	EcosystemID  string
	IdentityType proto.IdentityType
	Verifier     string
}

func (id AuthID) String() string {
	return strings.Join([]string{id.EcosystemID, string(id.IdentityType), id.Verifier}, "/")
}

func (id *AuthID) FromString(s string) error {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid auth session ID format: %s", s)
	}

	id.EcosystemID = parts[0]
	id.IdentityType = proto.IdentityType(parts[1])
	id.Verifier = parts[2]
	return nil
}

func (id *AuthID) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberS{Value: id.String()}, nil
}

func (id *AuthID) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid auth session ID of type: %T", value)
	}
	return id.FromString(v.Value)
}

type AuthCommitment struct {
	ID AuthID `dynamodbav:"ID"`

	EncryptedData EncryptedData[*proto.AuthCommitmentData] `dynamodbav:"EncryptedData"`
}

func (c *AuthCommitment) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ID": &types.AttributeValueMemberS{Value: c.ID.String()},
	}
}

func (c *AuthCommitment) CorrespondsTo(data *proto.AuthCommitmentData) bool {
	if c.ID.IdentityType != data.IdentityType {
		return false
	}
	if c.ID.Verifier != data.Verifier {
		return false
	}
	if c.ID.EcosystemID != data.EcosystemID {
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

func (t *AuthCommitmentTable) Get(ctx context.Context, authID AuthID) (*AuthCommitment, bool, error) {
	commitment := AuthCommitment{ID: authID}

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
