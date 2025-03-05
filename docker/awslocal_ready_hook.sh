#!/bin/bash

shopt -s expand_aliases

if [ ! "$(type -t awslocal)" = "alias" ] && [ ! -x "$(command -v awslocal)" ]; then
  alias awslocal="AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=${DEFAULT_REGION:-$AWS_DEFAULT_REGION} aws --endpoint-url=${LOCALSTACK_ENDPOINT:-http://${LOCALSTACK_HOST:-localhost}:4566}"
fi

awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"}]'
awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"aeb99e0f-9e89-44de-a084-e1817af47778"}]'

awslocal ses verify-email-identity --email-address noreply@local.auth.sequence.app

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name SignersTable \
  --attribute-definitions AttributeName=Ecosystem,AttributeType=S AttributeName=Identity,AttributeType=S AttributeName=Address,AttributeType=S \
  --key-schema AttributeName=Identity,KeyType=HASH AttributeName=Ecosystem,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
  "IndexName=Address-Index,KeySchema=[{AttributeName=Address,KeyType=HASH},{AttributeName=Ecosystem,KeyType=SORT}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=10,WriteCapacityUnits=10}"

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name AuthKeysTable \
  --attribute-definitions AttributeName=Ecosystem,AttributeType=S AttributeName=KeyID,AttributeType=S \
  --key-schema AttributeName=KeyID,KeyType=HASH AttributeName=Ecosystem,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name AuthCommitmentsTable \
  --attribute-definitions AttributeName=ID,AttributeType=S \
  --key-schema AttributeName=ID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name EncryptionPoolKeysTable \
  --attribute-definitions AttributeName=KeyID,AttributeType=S AttributeName=ConfigVersion,AttributeType=N AttributeName=KeyIndex,AttributeType=N \
  --key-schema AttributeName=ConfigVersion,KeyType=HASH AttributeName=KeyIndex,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
  "IndexName=KeyID-Index,KeySchema=[{AttributeName=KeyID,KeyType=HASH},{AttributeName=ConfigVersion,KeyType=SORT}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=10,WriteCapacityUnits=10}"

echo "Finished bootstrapping localstack resources!"
