"""
Utility methods for analysis-runner server
"""
import os
from shlex import quote
from typing import Any, Dict

from aiohttp import ClientSession, web
from analysis_runner.constants import ANALYSIS_RUNNER_PROJECT_ID
from cpg_utils.auth import check_dataset_access, get_user_from_headers
from cpg_utils.config import get_server_config
from google.cloud import pubsub_v1, secretmanager
from hailtop.config import get_deploy_config

GITHUB_ORG = 'populationgenomics'
METADATA_PREFIX = '/tmp/metadata'
PUBSUB_TOPIC = f'projects/{ANALYSIS_RUNNER_PROJECT_ID}/topics/submissions'
DRIVER_IMAGE = os.getenv('DRIVER_IMAGE')
assert DRIVER_IMAGE

COMBINE_METADATA = """
import json
import sys

def load(filename):
    text = open(filename).read().strip()
    val = json.loads(text) if len(text) else []
    return val if type(val) is list else [val]

print(json.dumps(load(sys.argv[1]) + load(sys.argv[2])))
"""

secret_manager = secretmanager.SecretManagerServiceClient()
publisher = pubsub_v1.PublisherClient()


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
    output_dir = f'gs://cpg-{dataset}-{bucket_type}/{output_suffix}'

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

    bucket_type = 'test' if access_level == 'test' else 'main'
    metadata_path = f'gs://cpg-{dataset}-{bucket_type}-analysis/metadata/{output_suffix}/analysis-runner.json'
    job.command(
        f'gsutil cp {quote(metadata_path)} {METADATA_PREFIX}_old.json '
        f'|| touch {METADATA_PREFIX}_old.json'
    )
    job.command(f'echo {quote(metadata_str)} > {METADATA_PREFIX}_new.json')
    job.command(f'echo "{COMBINE_METADATA}" > {METADATA_PREFIX}_combiner.py')
    job.command(
        f'python3 {METADATA_PREFIX}_combiner.py {METADATA_PREFIX}_old.json '
        f'{METADATA_PREFIX}_new.json > {METADATA_PREFIX}.json'
    )
    job.command(f'gsutil cp {METADATA_PREFIX}.json {quote(metadata_path)}')
