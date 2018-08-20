# upload_ssh_keys_to_aws
Command-line tool to import SSH public keys to AWS in an idempotent manner

## Requirements

### Tools

1. [Python3](https://www.python.org/download/releases/3.0/)
1. [Pip](https://pip.pypa.io/en/stable/)

### OS utilities required to be present in the environment path

1. openssl
1. ssh-keygen

### Credential setup

This tool uses boto3 and its default [authentication mechanisms](https://boto3.readthedocs.io/en/latest/guide/configuration.html) to interact with AWS.

## Usage

```
$ python upload_ssh_keys_to_aws.py -d <PATH_CONTAINING_PUBLIC_FILES>
```

## Recommended usage:

Use this tool along with a git repo of public keys to keep uploading your SSH keys to AWS.


## Upcoming features:

1. Command-line utility installable through pip.
1. Deletion of AWS keys not present in folder.
1. Interactive and hence selective import/deletion of key pairs.
1. Dockerized version to have all requirements pre-packaged.
