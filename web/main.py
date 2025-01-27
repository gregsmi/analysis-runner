"""Web server which proxies requests to per-dataset "web" buckets."""

import logging
import mimetypes
import os

from cpg_utils.auth import check_dataset_access, get_user_from_headers
from cpg_utils.storage import get_data_manager
from flask import Flask, Response, abort, request

BUCKET_SUFFIX = os.getenv('BUCKET_SUFFIX')
assert BUCKET_SUFFIX

app = Flask(__name__)

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

    # Don't allow reading `.access` files.
    if os.path.basename(filename) == '.access':
        abort(403)

    data_mgr = get_data_manager()

    # First chance: see whether user has dataset membership-based access.
    if not check_dataset_access(dataset, email, access_type='web-access'):
        # Second chance: if there's a '.access' file in the first subdirectory,
        # check if the email is listed there.
        split_subdir = filename.split('/', maxsplit=1)
        if len(split_subdir) == 2 and split_subdir[0]:
            access_list_filename = f'{split_subdir[0]}/.access'
            blob = data_mgr.get_blob(dataset, BUCKET_SUFFIX, access_list_filename)
            if blob is None:
                logger.warning(f'{email} is not a member of the {dataset} access group')
                abort(403)
            access_list = blob.decode('utf-8').splitlines()
            if email not in access_list:
                logger.warning(
                    f'{email} is not in {dataset} access group or {access_list_filename}'
                )
                abort(403)

    # Fetch the requested blob.
    blob = data_mgr.get_blob(dataset, BUCKET_SUFFIX, filename)
    if blob is None:
        abort(404)

    response = Response(blob)
    response.headers['Content-Type'] = (
        mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    )
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
