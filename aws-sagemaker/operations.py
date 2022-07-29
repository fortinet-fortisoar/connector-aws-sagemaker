""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


import boto3
from connectors.core.connector import get_logger, ConnectorError
from .utils import _get_aws_client, _get_temp_credentials

logger = get_logger('aws-ssagemaker')
TEMP_CRED_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{}'

def remove_unwanted_param(params):
    try:
        params.pop('aws_region', None)
        params.pop('assume_role', None)
        params.pop('session_name', None)
        params.pop('role_arn', None)
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        return param_dict
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def check_health(config):
    try:
        config_type = config.get('config_type')
        if config_type == "IAM Role":
            if _get_temp_credentials(config):
                return True
            else:
                logger.error('Invalid Role. Please verify is the role is associated to your instance.')
                raise ConnectorError('Invalid Role. Please verify is the role is associated to your instance.')
        else:
            aws_access_key = config.get('aws_access_key')
            aws_region = config.get('aws_region')
            aws_secret_access_key = config.get('aws_secret_access_key')
            client = boto3.client('sts', region_name=aws_region, aws_access_key_id=aws_access_key,
                                  aws_secret_access_key=aws_secret_access_key)
            account_id = client.get_caller_identity()["Account"]
            if account_id:
                return True
            else:
                logger.error('Invalid Region name or Aws Access Key ID or Aws Secret Access Key')
                raise ConnectorError('Invalid Region name or Aws Access Key ID or Aws Secret Access Key')
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_actions(config, params):
    try:
        client = _get_aws_client(config, params, 'sagemaker')
        param_dict = remove_unwanted_param(params)
        response = client.list_actions(**param_dict)
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_algorithms(config, params):
    try:
        client = _get_aws_client(config, params, 'sagemaker')
        param_dict = remove_unwanted_param(params)
        response = client.list_algorithms(**param_dict)
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_apps(config, params):
    try:
        client = _get_aws_client(config, params, 'sagemaker')
        param_dict = remove_unwanted_param(params)
        response = client.list_apps(**param_dict)
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_artifacts(config, params):
    try:
        client = _get_aws_client(config, params, 'sagemaker')
        param_dict = remove_unwanted_param(params)
        response = client.list_artifacts(**param_dict)
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


operations = {
    'get_actions': get_actions,
    'get_algorithms': get_algorithms,
    'get_apps': get_apps,
    'get_artifacts': get_artifacts
}
