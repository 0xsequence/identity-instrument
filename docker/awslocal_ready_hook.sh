#!/bin/bash

shopt -s expand_aliases

if [ ! "$(type -t awslocal)" = "alias" ] && [ ! -x "$(command -v awslocal)" ]; then
  alias awslocal="AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=${DEFAULT_REGION:-$AWS_DEFAULT_REGION} aws --endpoint-url=${LOCALSTACK_ENDPOINT:-http://${LOCALSTACK_HOST:-localhost}:4566}"
fi


if [ -n "$GOOGLE_CLIENT_ID" ] && [ -n "$GOOGLE_CLIENT_SECRET" ]; then
  awslocal secretsmanager create-secret --name "oauth/1/accounts.google.com/$GOOGLE_CLIENT_ID" --secret-string "{\"value\":\"$GOOGLE_CLIENT_SECRET\"}"
  awslocal secretsmanager create-secret --name "oauth/694/accounts.google.com/$GOOGLE_CLIENT_ID" --secret-string "{\"value\":\"$GOOGLE_CLIENT_SECRET\"}"
fi

if [ -n "$APPLE_CLIENT_ID" ] && [ -n "$APPLE_PRIVATE_KEY" ] && [ -n "$APPLE_KEY_ID" ] && [ -n "$APPLE_TEAM_ID" ]; then
  awslocal secretsmanager create-secret --name "oauth/1/appleid.apple.com/$APPLE_CLIENT_ID" --secret-string "{\"generate_jwt\":{\"claims\":{\"iss\":\"$APPLE_TEAM_ID\",\"aud\":\"https://appleid.apple.com\",\"sub\":\"$APPLE_CLIENT_ID\"},\"signing_key\":{\"private_key\":\"$APPLE_PRIVATE_KEY\",\"kid\":\"$APPLE_KEY_ID\",\"alg\":\"ES256\"}}}"
  awslocal secretsmanager create-secret --name "oauth/694/appleid.apple.com/$APPLE_CLIENT_ID" --secret-string "{\"generate_jwt\":{\"claims\":{\"iss\":\"$APPLE_TEAM_ID\",\"aud\":\"https://appleid.apple.com\",\"sub\":\"$APPLE_CLIENT_ID\"},\"signing_key\":{\"private_key\":\"$APPLE_PRIVATE_KEY\",\"kid\":\"$APPLE_KEY_ID\",\"alg\":\"ES256\"}}}"
fi

awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"}]'
awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"aeb99e0f-9e89-44de-a084-e1817af47778"}]'

awslocal ses verify-email-identity --email-address noreply@local.auth.sequence.app

awslocal secretsmanager create-secret \
  --region us-east-1 \
  --name BuilderJWT \
  --secret-string 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoiV2FhUyJ9.-FAkEOb0jtHhoHv6r4O7U8PGOw_b60M9MnSYN9Bm_7A'

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name SignersTable \
  --attribute-definitions AttributeName=ScopedKeyType,AttributeType=S AttributeName=IdentityHash,AttributeType=S AttributeName=Address,AttributeType=S AttributeName=CipherKeyRef,AttributeType=S AttributeName=CiphertextHash,AttributeType=B \
  --key-schema AttributeName=IdentityHash,KeyType=HASH AttributeName=ScopedKeyType,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
    '[
    {
      "IndexName": "Address-Index",
      "KeySchema": [
        {
          "AttributeName": "Address",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "ScopedKeyType",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    },
    {
      "IndexName": "CipherKeyRef-Index",
      "KeySchema": [
        {
          "AttributeName": "CipherKeyRef",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "CiphertextHash",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    }
    ]'

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name AuthKeysTable \
  --attribute-definitions AttributeName=Scope,AttributeType=S AttributeName=KeyHash,AttributeType=S AttributeName=CipherKeyRef,AttributeType=S AttributeName=CiphertextHash,AttributeType=B \
  --key-schema AttributeName=KeyHash,KeyType=HASH AttributeName=Scope,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
    '[
    {
      "IndexName": "CipherKeyRef-Index",
      "KeySchema": [
        {
          "AttributeName": "CipherKeyRef",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "CiphertextHash",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    }
    ]'
awslocal dynamodb update-time-to-live --region us-east-1 --table-name AuthKeysTable --time-to-live-specification "AttributeName=ExpiresAt,Enabled=true"

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name AuthCommitmentsTable \
  --attribute-definitions AttributeName=ID,AttributeType=S AttributeName=CipherKeyRef,AttributeType=S AttributeName=CiphertextHash,AttributeType=B \
  --key-schema AttributeName=ID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
    '[
    {
      "IndexName": "CipherKeyRef-Index",
      "KeySchema": [
        {
          "AttributeName": "CipherKeyRef",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "CiphertextHash",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    }
    ]'
awslocal dynamodb update-time-to-live --region us-east-1 --table-name AuthCommitmentsTable --time-to-live-specification "AttributeName=ExpiresAt,Enabled=true"

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name CipherKeysTable \
  --attribute-definitions AttributeName=KeyRef,AttributeType=S AttributeName=Generation,AttributeType=N AttributeName=KeyIndex,AttributeType=N AttributeName=InactiveSince,AttributeType=S \
  --key-schema AttributeName=KeyRef,KeyType=HASH AttributeName=Generation,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
    '[
    {
      "IndexName": "KeyIndex-Generation-Index",
      "KeySchema": [
        {
          "AttributeName": "KeyIndex",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "Generation",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    },
    {
      "IndexName": "Inactive-Index",
      "KeySchema": [
        {
          "AttributeName": "KeyRef",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "InactiveSince",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "KEYS_ONLY"
      },
      "ProvisionedThroughput": {
        "ReadCapacityUnits": 10,
        "WriteCapacityUnits": 10
      }
    }
    ]'

echo "Finished bootstrapping localstack resources!"
