"""Web server which proxies requests to per-dataset "web" buckets."""

import logging
import mimetypes
import os

import google.cloud.storage
from cpg_utils.auth import check_dataset_access, get_user_from_headers
from flask import Flask, Response, abort, request

ANALYSIS_RUNNER_PROJECT_ID = 'analysis-runner'

BUCKET_SUFFIX = os.getenv('BUCKET_SUFFIX')
assert BUCKET_SUFFIX

app = Flask(__name__)

storage_client = google.cloud.storage.Client()
logger = logging.getLogger('gunicorn.error')


@app.route('/<dataset>/<path:filename>')
def handler(dataset=None, filename=None):
    """Main entry point for serving."""
    if not dataset or not filename:
        logger.warning('Invalid request parameters')
        abort(400)

    email = get_user_from_headers(request.headers)
    if not email:
        logger.warning('Failed to extract email from ID token')
        abort(403)

    if not check_dataset_access(dataset, email, access_type='web-access'):
        logger.warning(f'{email} is not a member of the {dataset} web-access group')
        abort(403)

    bucket_name = f'cpg-{dataset}-{BUCKET_SUFFIX}'
    logger.info(f'Fetching blob gs://{bucket_name}/{filename}')
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.get_blob(filename)
    if blob is None:
        abort(404)

    response = Response(blob.download_as_bytes())
    response.headers['Content-Type'] = (
        mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    )
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
