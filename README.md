# upload_ssh_keys_to_aws
Command-line tool to import SSH public keys to AWS in an idempotent manner

## Docker Version

### Requirements

* Docker: The dockerized version is a better way to use run this tool given it has the installation of all the necessary tools handled internally.

### Usage

With API Keys as environment variables

```
$ docker run \
  -v <ABSOLUTE_PATH_TO_KEYS_FOLDER>:/keys \
  -e "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID" \
  -e "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" \
  -e "AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION" \
  sync_ssh_keys_to_aws -d /keys -l DEBUG
```

With API Keys in credentials file

```
$ docker run \
  -v <ABSOLUTE_PATH_TO_KEYS_FOLDER>:/keys \
  -v <ABSOLUTE_PATH_TO_HOME>/.aws/credentials:/root/.aws/credentials \
  -e "AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION" \
  sync_ssh_keys_to_aws -d /keys -l DEBUG
```

## Native Version

### Requirements

#### Tools

* [Python3](https://www.python.org/download/releases/3.0/)
* [Pip](https://pip.pypa.io/en/stable/)

#### OS utilities required to be present in the environment path

* openssl
* ssh-keygen

#### Credential setup

This tool uses boto3 and its default [authentication mechanisms](https://boto3.readthedocs.io/en/latest/guide/configuration.html) to interact with AWS.

### Usage

```
$ python upload_ssh_keys_to_aws.py -d <PATH_CONTAINING_PUBLIC_FILES>
```


## Upcoming features:

* ~~Command-line utility installable through pip.~~
* Deletion of public keys from AWS not present in folder.
* Interactive and hence selective import/deletion of key pairs.
* Dockerized version to have all requirements pre-packaged. :white_check_mark:
