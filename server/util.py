"""
Utility methods for analysis-runner server
"""
import os
import uuid
from shlex import quote
from typing import Any, Dict

import toml
from aiohttp import ClientSession, web
from cloudpathlib import AnyPath
from cpg_utils.auth import check_dataset_access, get_user_from_headers
from cpg_utils.deploy_config import get_deploy_config, get_server_config
from cpg_utils.storage import get_dataset_bucket_url
from hailtop.config import get_deploy_config as get_hail_deploy_config
from sample_metadata.apis import AnalysisApi

DRIVER_IMAGE = os.getenv('DRIVER_IMAGE')
assert DRIVER_IMAGE
REFERENCE_PREFIX = 'gs://cpg-reference'


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
    **kwargs,
):
    """
    Get well-formed analysis-runner metadata, requiring the core listed keys
    with some flexibility to provide your own keys (as **kwargs)
    """
    bucket_type = 'test' if access_level == 'test' else 'main'
    output_dir = f'gs://cpg-{dataset}-{bucket_type}/{output_prefix}'

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
        **kwargs,
    }


def run_batch_job_and_print_url(batch, wait):
    """Call batch.run(), return the URL, and wait for job to  finish if wait=True"""
    bc_batch = batch.run(wait=False)

    hail_deploy_config = get_hail_deploy_config()
    url = hail_deploy_config.url('batch', f'/batches/{bc_batch.id}')

    if wait:
        status = bc_batch.wait()
        if status['state'] != 'success':
            raise web.HTTPBadRequest(reason=f'{url} failed')

    return url


def write_metadata_to_bucket(
    job, access_level: str, dataset: str, output_prefix: str, metadata_str: str
):
    """
    Copy analysis-runner.json to the metadata bucket

    Append metadata information, in case the same
    output directory gets used multiple times.
    """

    bucket_type = ('test' if access_level == 'test' else 'main') + '-analysis'
    blob_path = f'metadata/{output_prefix}/analysis-runner.json'

    script_path = os.path.join(os.path.dirname(__file__), 'append_metadata.py')
    with open(script_path, encoding='utf-8') as f:
        script = f.read()

    job.command(f'echo {quote(script)} > append_metadata.py')
    job.command(
        f'python3 append_metadata.py '
        f'{dataset} {bucket_type} {blob_path} {quote(metadata_str)}'
    )


def add_analysis_metadata(metadata: Dict[str, str]) -> None:
    project = metadata.pop('dataset')
    output_dir = metadata.pop('output')
    metadata['source'] = 'analysis-runner'
    access_level = metadata.get('accessLevel')

    if access_level == 'test':
        project += '-test'

    analysis_model = {
        'sample_ids': [],
        'type': 'custom',
        'status': 'unknown',
        'output': output_dir,
        'author': metadata.pop('user'),
        'meta': metadata,
        'active': False,
    }

    analysis = AnalysisApi()
    analysis.create_new_analysis(project, analysis_model)
    # TODO GRS update airtable as well


def get_registry_prefix() -> str:
    deploy_config = get_deploy_config()
    return f'{deploy_config.container_registry}/cpg-common/images'


def get_web_url_template() -> str:
    deploy_config = get_deploy_config()
    return f'https://{{namespace}}-{deploy_config.web_host_base}/{{dataset}}'


def validate_image(container: str) -> bool:
    """
    Check that the image is valid for the access_level
    """
    registry = get_deploy_config().container_registry
    allowed = [f'{registry}/{suffix}/' for suffix in ['analysis-runner', 'cpg-common']]
    return any(container.startswith(prefix) for prefix in allowed)


def write_config(config: dict) -> str:
    """Writes the given config dictionary to a blob and returns its unique path."""
    # get_config will recognize this section and load the deployment config.
    config['CPG_DEPLOY_CONFIG'] = get_deploy_config().to_dict()
    config_bucket = get_dataset_bucket_url(None, 'config')
    config_path = AnyPath(config_bucket) / (str(uuid.uuid4()) + '.toml')
    with config_path.open('w') as f:
        toml.dump(config, f)
    return str(config_path)
