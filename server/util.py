# pylint: disable=too-many-function-args
"""
Utility methods for analysis-runner server
"""
import os
import uuid
from typing import Any, Dict

import toml
from aiohttp import ClientSession, web
from cloudpathlib import AnyPath
from cpg_utils.auth import check_dataset_access, get_user_from_headers
from cpg_utils.deploy_config import get_deploy_config, get_server_config
from cpg_utils.storage import get_dataset_bucket_config, get_dataset_bucket_url, get_global_bucket_url
from cpg_utils.hail_batch import cpg_namespace
from hailtop.config import get_deploy_config as get_hail_deploy_config
from sample_metadata.apis import AnalysisApi

DRIVER_IMAGE = os.getenv('DRIVER_IMAGE')
assert DRIVER_IMAGE


async def _get_hail_version() -> str:
    """ASYNC get hail version for the hail server in the local deploy_config"""
    hail_deploy_config = get_hail_deploy_config()
    url = hail_deploy_config.url('batch', f'/api/v1alpha/version')
    async with ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text()


def get_email_from_request(request):
    """Use cpg-utils to extract user from already-authenticated request headers."""
    user = get_user_from_headers(request.headers)
    if not user:
        raise web.HTTPForbidden(reason='Invalid authorization header')
    return user


def validate_output_dir(output_dir: str):
    """Checks that output_dir doesn't start with 'gs://' and strips trailing slashes."""
    if output_dir.startswith('gs://'):
        raise web.HTTPBadRequest(reason='Output directory cannot start with "gs://"')
    return output_dir.rstrip('/')  # Strip trailing slash.


def validate_dataset_access(dataset: str, user: str, repo: str) -> Dict[str, Any]:
    server_config = get_server_config()

    # Make sure dataset exists in server-config.
    dataset_config = server_config.get(dataset)
    if not dataset_config:
        raise web.HTTPForbidden(
            reason=f'Dataset "{dataset}" is not part of: {", ".join(server_config.keys())}'
        )

    # Make sure specified user has access to the dataset.
    if not check_dataset_access(dataset, user, access_type='access'):
        raise web.HTTPForbidden(
            reason=f'{user} is not a member of the {dataset} access group'
        )

    # Check that repo is the in server-config allowedRepos for the dataset.
    allowed_repos = dataset_config['allowedRepos']
    if repo not in allowed_repos:
        raise web.HTTPForbidden(
            reason=(
                f'Repository "{repo}" is not one of the allowed repositories: {", ".join(allowed_repos)}'
            )
        )

    return dataset_config


# pylint: disable=too-many-arguments
def get_analysis_runner_metadata(
    timestamp,
    dataset,
    user,
    access_level,
    repo,
    commit,
    script,
    description,
    output_prefix,
    driver_image,
    config_path,
    cwd,
    environment,
    **kwargs,
):
    """
    Get well-formed analysis-runner metadata, requiring the core listed keys
    with some flexibility to provide your own keys (as **kwargs)
    """
    bucket_type = 'test' if access_level == 'test' else 'main'
    output_dir = f'{get_dataset_bucket_url(dataset, bucket_type)}/{output_prefix}'

    return {
        'timestamp': timestamp,
        'dataset': dataset,
        'user': user,
        'accessLevel': access_level,
        'repo': repo,
        'commit': commit,
        'script': script,
        'description': description,
        'output': output_dir,
        'driverImage': driver_image,
        'configPath': config_path,
        'cwd': cwd,
        'environment': environment,
        **kwargs,
    }


def run_batch_job_and_print_url(batch, wait, environment):
    """Call batch.run(), return the URL, and wait for job to  finish if wait=True"""
    bc_batch = batch.run(wait=False)

    hail_deploy_config = get_hail_deploy_config()
    url = hail_deploy_config.url('batch', f'/batches/{bc_batch.id}')

    if wait:
        status = bc_batch.wait()
        if status['state'] != 'success':
            raise web.HTTPBadRequest(reason=f'{url} failed')

    return url


def validate_image(container) -> bool:
    """
    Check that the image is valid for the access_level
    """
    registry = get_deploy_config().container_registry
    allowed = [f'{registry}/{suffix}/' for suffix in ['analysis-runner', 'cpg-common']]
    return any(container.startswith(prefix) for prefix in allowed)


def write_config(config: dict, environment: str) -> str:
    """Writes the given config dictionary to a blob and returns its unique path."""
    # get_config will recognize this section and load the deployment config.
    config['CPG_DEPLOY_CONFIG'] = get_deploy_config().to_dict()
    config_path = AnyPath(get_global_bucket_url('config')) / (str(uuid.uuid4()) + '.toml')
    with config_path.open('w') as f:
        toml.dump(config, f)
    return str(config_path)


def get_baseline_run_config(
    environment: str,
    gcp_project_id,
    dataset,
    access_level,
    output_prefix,
    driver: str,
) -> dict:
    """
    Returns the baseline config of analysis-runner specified default values,
    as well as pre-generated templates with common locations and resources.
    """
    baseline_config = {
        'hail': {
            'billing_project': dataset,
            'bucket': get_dataset_bucket_url(dataset, 'hail'),
        },
        'workflow':  {
            'access_level': access_level,
            'dataset': dataset,
            'dataset_gcp_project': gcp_project_id,
            'driver_image': driver,
            'output_prefix': output_prefix,
        },
        'storage': { dataset : get_dataset_bucket_config(dataset, access_level)},
    }

    # Our version of AR relies on the caller to pass in [images] and [references] sections.
    # template_paths = [
    #     AnyPath(config_prefix) / 'templates' / suf
    #     for suf in [
    #         'images/images.toml',
    #         'references/references.toml',
    #         f'storage/{environment}/{dataset}-{cpg_namespace(access_level)}.toml',
    #     ]
    # ]
    # if missing := [p for p in template_paths if not p.exists()]:
    #     raise ValueError(f'Missing expected template configs: {missing}')

    # for path in template_paths:
    #     with path.open() as f:
    #         update_dict(baseline_config, toml.load(f))

    return baseline_config
