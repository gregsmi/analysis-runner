"""
Utility methods for analysis-runner server
"""
import os
from shlex import quote
from typing import Any, Dict

from aiohttp import ClientSession, web
from cpg_utils.auth import check_dataset_access, get_user_from_headers
from cpg_utils.config import get_server_config
from hailtop.config import get_deploy_config
from sample_metadata.apis import AnalysisApi

DRIVER_IMAGE = os.getenv('DRIVER_IMAGE')
assert DRIVER_IMAGE


async def _get_hail_version() -> str:
    """ASYNC get hail version for the hail server in the local deploy_config"""
    deploy_config = get_deploy_config()
    url = deploy_config.url('query', f'/api/v1alpha/version')
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
    output_suffix,
    driver_image,
    cwd,
    **kwargs,
):
    """
    Get well-formed analysis-runner metadata, requiring the core listed keys
    with some flexibility to provide your own keys (as **kwargs)
    """
    bucket_type = 'test' if access_level == 'test' else 'main'
    output_dir = f'cpg-{dataset}-{bucket_type}/{output_suffix}'

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
        'cwd': cwd,
        **kwargs,
    }


def run_batch_job_and_print_url(batch, wait):
    """Call batch.run(), return the URL, and wait for job to  finish if wait=True"""
    bc_batch = batch.run(wait=False)

    deploy_config = get_deploy_config()
    url = deploy_config.url('batch', f'/batches/{bc_batch.id}')

    if wait:
        status = bc_batch.wait()
        if status['state'] != 'success':
            raise web.HTTPBadRequest(reason=f'{url} failed')

    return url


def write_metadata_to_bucket(
    job, access_level: str, dataset: str, output_suffix: str, metadata_str: str
):
    """
    Copy analysis-runner.json to the metadata bucket

    Append metadata information, in case the same
    output directory gets used multiple times.
    """

    bucket_type = ('test' if access_level == 'test' else 'main') + '-analysis'
    blob_path = f'metadata/{output_suffix}/analysis-runner.json'

    script_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), 'append_metadata.py')
    )
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
