FROM python:3.7.0-alpine

COPY requirements.txt /

RUN apk add --update openssl && \
    apk add --update openssh && \
    pip install -r /requirements.txt

COPY upload_ssh_keys_to_aws.py /

ENTRYPOINT ["/upload_ssh_keys_to_aws.py"]
