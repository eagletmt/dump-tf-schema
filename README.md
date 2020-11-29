# dump-tf-schema
Dump schema of Terraform providers

## Usage
```
% dump-tf-schema -n hashicorp -t aws > aws.json
[2020-11-29T17:20:06Z INFO  dump_tf_schema] Downloading https://releases.hashicorp.com/terraform-provider-aws/3.18.0/terraform-provider-aws_3.18.0_linux_amd64.zip to /tmp/dump-tf-schema-VIZJB4.zip
[2020-11-29T17:20:08Z INFO  dump_tf_schema] Unarchiving terraform-provider-aws_v3.18.0_x5 to /tmp/dump-tf-schema-0HHVTU
{"@level":"debug","@message":"plugin address","@timestamp":"2020-11-30T02:20:09.010543+09:00","address":"/tmp/plugin872403236","network":"unix"}
% head -50 aws.json
{
  "resource_schemas": {
    "aws_codeartifact_repository": {
      "attributes": {
        "domain": "String",
        "tags": {
          "Map": "String"
        },
        "repository": "String",
        "administrator_account": "String",
        "id": "String",
        "arn": "String",
        "description": "String",
        "domain_owner": "String"
      },
      "blocks": {
        "external_connections": {
          "block": {
            "attributes": {
              "external_connection_name": "String",
              "package_format": "String",
              "status": "String"
            },
            "blocks": {}
          },
          "min_items": 0,
          "max_items": 1
        },
        "upstream": {
          "block": {
            "attributes": {
              "repository_name": "String"
            },
            "blocks": {}
          },
          "min_items": 0,
          "max_items": 0
        }
      }
    },
    "aws_iam_policy_attachment": {
      "attributes": {
        "policy_arn": "String",
        "roles": {
          "Set": "String"
        },
        "users": {
          "Set": "String"
        },
        "name": "String",
```
