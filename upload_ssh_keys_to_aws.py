#!/usr/bin/env python

import argparse
import boto3
import logging
import os
import glob
import subprocess
from botocore.exceptions import ClientError

LOG_LEVEL_MAPPINGS = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

class LocalKeyPair():
    def __init__(self, local_path):
        self.name = os.path.split(local_path)[1].replace('.pub','')
        self.absolute_path = local_path
        self.exists_on_aws, self.remote_fingerprint = self._get_remote_fingerprint()

    def upsert(self):
        if not self.exists_on_aws:
            self._upload()
        elif self.exists_on_aws and self.remote_fingerprint != self._calculate_fingerprint():
            logging.debug('Going to replace the key pair on AWS')
            self._delete()
            self._upload()
        else:
            logging.info('Key pair already exists on AWS with name {} and fingerprint {}'.format(self.name, self.remote_fingerprint))


    def _upload(self):
        ec2_client = boto3.client('ec2')
        public_key_material = self._base64_encoded_public_key()
        logging.debug('Public Key Material: {}'.format(public_key_material))
        try:
            ec2_client.import_key_pair(
                KeyName=self.name,
                PublicKeyMaterial=public_key_material
            )
        except ClientError as e:
            logging.critical('Failed to upload key {} with error "{}"'.format(self.name, e.response['Error']['Message']))


    def _delete(self):
        raise NotImplementedError

    def _calculate_fingerprint(self):
        ssh_keygen_output_file = "/tmp/ssh_keygen_output"
        openssl_pkey_output_file = "/tmp/openssl_pkey_output"
        ssh_keygen_command = "ssh-keygen -e -f {} -m pkcs8".format(self.absolute_path)
        openssl_pkey_command = "openssl pkey -pubin -outform der -in {}".format(ssh_keygen_output_file)
        openssl_md5_command = "openssl md5 -c {}".format(openssl_pkey_output_file)
        self._run_command(ssh_keygen_command, output_file=ssh_keygen_output_file)
        self._run_command(openssl_pkey_command, output_file=openssl_pkey_output_file)
        openssl_md5_output = self._run_command(openssl_md5_command)
        fingerprint = openssl_md5_output.decode("utf-8").split("=")[-1].strip()
        return fingerprint

    def _write_to_file(self, file, contents):
        file_handle = open(file, "wb")
        file_handle.write(contents)
        file_handle.close()

    def _run_command(self, command, output_file=None):
        output = subprocess.check_output(command.split())
        if output_file is not None:
            file_handle = open(output_file, "wb")
            file_handle.write(output)
            file_handle.close()
        else:
            return output

    def _base64_encoded_public_key(self):
        file = open(self.absolute_path, 'r')
        encoded_key = file.read().strip().encode()
        file.close()
        return encoded_key

    def _get_remote_fingerprint(self):
        ec2_client = boto3.client('ec2')
        try:
            keypairs = ec2_client.describe_key_pairs(KeyNames=[self.name])['KeyPairs']
            return True, keypairs[0]['KeyFingerprint']
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                return False, None
            else:
                logging.critical(e.response['Error']['Message'])
                exit(1)

def get_all_public_key_files(folder):
    lookup_string = os.path.join(folder, '*.pub')
    files = glob.glob(lookup_string)
    logging.info('Public Key files found in folder {}:'.format(folder))
    for file in files:
        logging.info(file)
    return files

def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=LOG_LEVEL_MAPPINGS[args.log_level])
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    all_public_key_files = get_all_public_key_files(args.directory)
    for public_key_file in all_public_key_files:
        key_pair = LocalKeyPair(public_key_file).upsert()

parser = argparse.ArgumentParser()
parser.add_argument(
    "-d",
    "--directory",
    help="Directory in which .pub files are to be searched",
    action="store",
    required=True)
parser.add_argument(
    "-l",
    "--log-level",
    choices=[key for key in LOG_LEVEL_MAPPINGS],
    help="Log level",
    action="store",
    default='DEBUG')
parser.add_argument(
    "--temp-directory",
    default="/tmp",
    action="store",
    help="Temporary directory to write files to"
)
args = parser.parse_args()

if __name__ == '__main__':
    main()
