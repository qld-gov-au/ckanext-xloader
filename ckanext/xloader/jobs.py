from __future__ import division
from __future__ import absolute_import
import math
import logging
import hashlib
import time
import tempfile
import json
import datetime
import traceback
import sys

from six.moves.urllib.parse import urlsplit
import requests
from rq import get_current_job
import sqlalchemy as sa

from ckan.plugins.toolkit import get_action, asbool, ObjectNotFound, config
from ckan.lib.uploader import get_resource_uploader

from . import loader
from . import db
from .job_exceptions import JobError, HTTPError, DataTooBigError, FileCouldNotBeLoadedError
from .utils import set_resource_metadata, get_xloader_user_context


SSL_VERIFY = asbool(config.get('ckanext.xloader.ssl_verify', True))
if not SSL_VERIFY:
    requests.packages.urllib3.disable_warnings()

MAX_CONTENT_LENGTH = int(config.get('ckanext.xloader.max_content_length') or 1e9)
MAX_EXCERPT_LINES = int(config.get('ckanext.xloader.max_excerpt_lines') or 0)
CHUNK_SIZE = 16 * 1024  # 16kb
DOWNLOAD_TIMEOUT = 30


# input = {
# 'job_type': 'xloader_to_datastore',
# 'metadata': {
#     'ignore_hash': data_dict.get('ignore_hash', False),
#     'ckan_url': site_url,
#     'resource_id': res_id,
#     'set_url_type': data_dict.get('set_url_type', False),
#     'task_created': task['last_updated'],
#     'original_url': resource_dict.get('url'),
#     }
# }

def _get_logger(database_logging=True, job_id=None):
    logger = logging.getLogger('%s.%s' % (__name__, job_id)
                               if job_id else __name__)

    if database_logging:
        # Set-up logging to the db
        db_handler = StoringHandler(job_id, input)
        db_handler.setLevel(logging.DEBUG)
        db_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(db_handler)

    return logger


def xloader_data_into_datastore(input):
    '''This is the func that is queued. It is a wrapper for
    xloader_data_into_datastore_, and makes sure it finishes by calling
    xloader_hook to update the task_status with the result.

    Errors are stored in task_status and job log and this method returns
    'error' to let RQ know too. Should task_status fails, then we also return
    'error'.
    '''
    # First flag that this task is running, to indicate the job is not
    # stillborn, for when xloader_submit is deciding whether another job would
    # be a duplicate or not
    job_dict = dict(metadata=input['metadata'],
                    status='running')

    logger = _get_logger(database_logging=False)

    callback_xloader_hook(job_dict=job_dict, logger=logger)

    job_id = get_current_job().id
    errored = False
    try:
        xloader_data_into_datastore_(input, job_dict)
        job_dict['status'] = 'complete'
        db.mark_job_as_completed(job_id, job_dict)
    except JobError as e:
        db.mark_job_as_errored(job_id, str(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        logger.error('xloader error: {0}, {1}'.format(e, traceback.format_exc()))
        errored = True
    except Exception as e:
        db.mark_job_as_errored(
            job_id, traceback.format_tb(sys.exc_info()[2])[-1] + repr(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        logger.error('xloader error: {0}, {1}'.format(e, traceback.format_exc()))
        errored = True
    finally:
        # job_dict is defined in xloader_hook's docstring
        is_saved_ok = callback_xloader_hook(job_dict=job_dict, logger=logger)
        errored = errored or not is_saved_ok
    return 'error' if errored else None


def xloader_data_into_datastore_(input, job_dict):
    '''This function:
    * downloads the resource (metadata) from CKAN
    * downloads the data
    * calls the loader to load the data into DataStore
    * calls back to CKAN with the new status

    (datapusher called this function 'push_to_datastore')
    '''
    job_id = get_current_job().id
    db.init(config)

    # Store details of the job in the db
    try:
        db.add_pending_job(job_id, **input)
    except sa.exc.IntegrityError:
        raise JobError('job_id {} already exists'.format(job_id))

    logger = _get_logger(job_id=job_id)

    validate_input(input)

    data = input['metadata']

    resource_id = data['resource_id']
    try:
        resource, dataset = get_resource_and_dataset(resource_id)
    except (JobError, ObjectNotFound):
        # try again in 5 seconds just in case CKAN is slow at adding resource
        time.sleep(5)
        resource, dataset = get_resource_and_dataset(resource_id)
    resource_ckan_url = '/dataset/{}/resource/{}' \
        .format(dataset['name'], resource['id'])
    logger.info('Express Load starting: %s', resource_ckan_url)

    # check if the resource url_type is a datastore
    accept_types = ['upload', '', None]
    if resource.get('url_type') not in accept_types:
        logger.info('Ignoring resource - url_type=datastore - dump files are '
                    'managed with the Datastore API')
        return

    # download resource
    tmp_file, file_hash = _download_resource_data(resource, data, logger)

    if (resource.get('hash') == file_hash
            and not data.get('ignore_hash')):
        logger.info('Ignoring resource - the file hash hasn\'t changed: '
                    '{hash}.'.format(hash=file_hash))
        return
    logger.info('File hash: %s', file_hash)
    resource['hash'] = file_hash

    def direct_load():
        fields = loader.load_csv(
            tmp_file.name,
            resource_id=resource['id'],
            mimetype=resource.get('format'),
            logger=logger)
        loader.calculate_record_count(
            resource_id=resource['id'], logger=logger)
        set_datastore_active(data, resource, logger)
        job_dict['status'] = 'running_but_viewable'
        callback_xloader_hook(job_dict=job_dict, logger=logger)
        logger.info('Data now available to users: %s', resource_ckan_url)
        loader.create_column_indexes(
            fields=fields,
            resource_id=resource['id'],
            logger=logger)
        update_resource(resource={'id': resource['id'], 'hash': resource['hash']},
                        patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    def tabulator_load():
        try:
            loader.load_table(tmp_file.name,
                              resource_id=resource['id'],
                              mimetype=resource.get('format'),
                              logger=logger)
        except JobError as e:
            logger.error('Error during tabulator load: %s', e)
            raise
        loader.calculate_record_count(
            resource_id=resource['id'], logger=logger)
        set_datastore_active(data, resource, logger)
        logger.info('Finished loading with tabulator')
        update_resource(resource={'id': resource['id'], 'hash': resource['hash']},
                        patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    # Load it
    logger.info('Loading CSV')
    # If ckanext.xloader.use_type_guessing is not configured, fall back to
    # deprecated ckanext.xloader.just_load_with_messytables
    use_type_guessing = asbool(config.get(
        'ckanext.xloader.use_type_guessing', config.get(
            'ckanext.xloader.just_load_with_messytables', False)))
    logger.info("'use_type_guessing' mode is: %s",
                use_type_guessing)
    try:
        if use_type_guessing:
            tabulator_load()
        else:
            try:
                direct_load()
            except JobError as e:
                logger.warning('Load using COPY failed: %s', e)
                just_load_with_direct_load = asbool(config.get(
                    'ckanext.xloader.just_load_with_direct_load', False))
                logger.info("'Just load with direct load' mode is: {}".format(
                    just_load_with_direct_load))
                if just_load_with_direct_load:
                    logger.info('Skipping messytables loading')
                    # at this point, the loading has fully failed. Re-raising the error
                    # so it is caught by this method's wrapper:
                    #       xloader_data_into_datastore
                    # (canada fork only)
                    # TODO: upstream contribution??
                    raise JobError(e)
                else:
                    logger.info('Trying again with tabulator')
                    tabulator_load()
    except FileCouldNotBeLoadedError as e:
        logger.warning('Loading excerpt for this format not supported.')
        logger.error('Loading file raised an error: %s', e)
        raise JobError('Loading file raised an error: {}'.format(e))

    tmp_file.close()

    logger.info('Express Load completed')


def _download_resource_data(resource, data, logger):
    '''Downloads the resource['url'] as a tempfile.

    :param resource: resource (i.e. metadata) dict (from the job dict)
    :param data: job dict - may be written to during this function
    :param logger:

    If the download is bigger than MAX_CONTENT_LENGTH then it just downloads a
    excerpt (of MAX_EXCERPT_LINES) for preview, and flags it by setting
    data['datastore_contains_all_records_of_source_file'] = False
    which will be saved to the resource later on.
    '''
    url = resource.get('url')
    url_parts = urlsplit(url)
    scheme = url_parts.scheme

    # check if it is an uploaded file
    domain = url_parts.netloc
    site_url = config.get('ckan.site_url')
    if resource.get('url_type') != 'upload' and domain != site_url:
        raise JobError('Only uploaded files can be added to the Data Store.')

    # get url from uploader (canada fork only)
    #TODO: upstream contribution??
    upload = get_resource_uploader(resource)
    url = upload.get_path(resource['id'])
    logger.info('Resource %s using uploader: %s', resource['id'], type(upload).__name__)

    # check scheme
    url_parts = urlsplit(url)
    scheme = url_parts.scheme
    if scheme not in ('http', 'https', 'ftp'):
        raise JobError(
            'Only http, https, and ftp resources may be fetched.'
        )

    # fetch the resource data
    logger.info('Fetching from: {0}'.format(url))
    tmp_file = get_tmp_file(url)
    length = 0
    m = hashlib.md5()
    cl = None
    try:
        headers = {}
        if resource.get('url_type') == 'upload':
            # Add a constantly changing parameter to bypass URL caching.
            # If we're running XLoader, then either the resource has
            # changed, or something went wrong and we want a clean start.
            # Either way, we don't want a cached file.
            download_url = url_parts._replace(
                query='{}&nonce={}'.format(url_parts.query, time.time())
            ).geturl()
        else:
            download_url = url

        response = get_response(download_url, headers)

        cl = response.headers.get('content-length')
        if cl and int(cl) > MAX_CONTENT_LENGTH:
            response.close()
            raise DataTooBigError()

        # download the file to a tempfile on disk
        for chunk in response.iter_content(CHUNK_SIZE):
            length += len(chunk)
            if length > MAX_CONTENT_LENGTH:
                raise DataTooBigError
            tmp_file.write(chunk)
            m.update(chunk)
        response.close()
        data['datastore_contains_all_records_of_source_file'] = True

    except DataTooBigError:
        tmp_file.close()
        message = 'Data too large to load into Datastore: ' \
            '{cl} bytes > max {max_cl} bytes.' \
            .format(cl=cl or length, max_cl=MAX_CONTENT_LENGTH)
        logger.warning(message)
        if MAX_EXCERPT_LINES <= 0:
            raise JobError(message)
        logger.info('Loading excerpt of ~{max_lines} lines to '
                    'DataStore.'
                    .format(max_lines=MAX_EXCERPT_LINES))
        tmp_file = get_tmp_file(url)
        response = get_response(url, headers)
        length = 0
        line_count = 0
        m = hashlib.md5()
        for line in response.iter_lines(CHUNK_SIZE):
            tmp_file.write(line + b'\n')
            m.update(line)
            length += len(line)
            line_count += 1
            if length > MAX_CONTENT_LENGTH or line_count >= MAX_EXCERPT_LINES:
                break
        response.close()
        data['datastore_contains_all_records_of_source_file'] = False
    except requests.exceptions.HTTPError as error:
        # status code error
        logger.debug('HTTP error: %s', error)
        raise HTTPError(
            "Xloader received a bad HTTP response when trying to download "
            "the data file", status_code=error.response.status_code,
            request_url=url, response=error)
    except requests.exceptions.Timeout:
        logger.warning('URL time out after %ss', DOWNLOAD_TIMEOUT)
        raise JobError('Connection timed out after {}s'.format(
                       DOWNLOAD_TIMEOUT))
    except requests.exceptions.RequestException as e:
        try:
            err_message = str(e.reason)
        except AttributeError:
            err_message = str(e)
        logger.warning('URL error: %s', err_message)
        raise HTTPError(
            message=err_message, status_code=None,
            request_url=url, response=None)

    logger.info('Downloaded ok - %s', printable_file_size(length))
    file_hash = m.hexdigest()
    # remove NULL bytes from the data (canada fork only)
    # TODO: upstream contribution??
    tmp_file.seek(0)
    tmp_data = tmp_file.read()
    tmp_file.close()
    parsed_tmp_file = get_tmp_file(url)
    # removes white space at end as well (canad fork only)
    parsed_tmp_file.write(tmp_data.replace('\x00', '').replace('\0', '').rstrip())
    parsed_tmp_file.seek(0)
    return parsed_tmp_file, file_hash


def get_response(url, headers):
    def get_url():
        kwargs = {'headers': headers, 'timeout': DOWNLOAD_TIMEOUT,
                  'verify': SSL_VERIFY, 'stream': True}  # just gets the headers for now
        if 'ckan.download_proxy' in config:
            proxy = config.get('ckan.download_proxy')
            kwargs['proxies'] = {'http': proxy, 'https': proxy}
        return requests.get(url, **kwargs)
    response = get_url()
    if response.status_code == 202:
        # Seen: https://data-cdfw.opendata.arcgis.com/datasets
        # In this case it means it's still processing, so do retries.
        # 202 can mean other things, but there's no harm in retries.
        wait = 1
        while wait < 120 and response.status_code == 202:
            # logger.info('Retrying after %ss', wait)
            time.sleep(wait)
            response = get_url()
            wait *= 3
    response.raise_for_status()
    return response


def get_tmp_file(url):
    filename = url.split('/')[-1].split('#')[0].split('?')[0]
    tmp_file = tempfile.NamedTemporaryFile(suffix=filename)
    return tmp_file


def set_datastore_active(data, resource, logger):
    if data.get('set_url_type', False):
        logger.debug('Setting resource.url_type = \'datapusher\'')
        resource['url_type'] = 'datapusher'
        update_resource(resource)

    data['datastore_active'] = True
    logger.info('Setting resource.datastore_active = True')
    contains_all_records = data.get(
        'datastore_contains_all_records_of_source_file', True)
    data['datastore_contains_all_records_of_source_file'] = contains_all_records
    logger.info(
        'Setting resource.datastore_contains_all_records_of_source_file = %s',
        contains_all_records)
    set_resource_metadata(update_dict=data)


def callback_xloader_hook(job_dict, logger):
    '''Tells CKAN about the result of the xloader (i.e. calls the action
    function 'xloader_hook'). Usually called by the xloader queue job.

    Returns whether it managed to call the xloader_hook action or not
    '''
    try:
        get_action('xloader_hook')(get_xloader_user_context(), job_dict)
    except Exception as e:
        logger.warning("Failed to call xloader_hook action: %s", e)
        return False

    return True


def validate_input(input):
    # Especially validate metadata which is provided by the user
    if 'metadata' not in input:
        raise JobError('Metadata missing')

    data = input['metadata']

    if 'resource_id' not in data:
        raise JobError('No id provided.')
    if 'ckan_url' not in data:
        raise JobError('No ckan_url provided.')


def update_resource(resource, patch_only=False):
    """
    Update the given CKAN resource to say that it has been stored in datastore
    ok.
    or patch the given CKAN resource for file hash
    """
    action = 'resource_update' if not patch_only else 'resource_patch'
    context = get_xloader_user_context()
    context['ignore_auth'] = True
    context['auth_user_obj'] = None
    get_action(action)(context, resource)


def get_resource_and_dataset(resource_id):
    """
    Gets available information about the resource and its dataset from CKAN
    """
    context = get_xloader_user_context()
    res_dict = get_action('resource_show')(context, {'id': resource_id})
    pkg_dict = get_action('package_show')(context, {'id': res_dict['package_id']})
    return res_dict, pkg_dict


def check_response(response, request_url, who, good_status=(201, 200),
                   ignore_no_success=False):
    """
    Checks the response and raises exceptions if something went terribly wrong

    :param who: A short name that indicated where the error occurred
                (for example "CKAN")
    :param good_status: Status codes that should not raise an exception

    """
    if not response.status_code:
        raise HTTPError(
            'Xloader received an HTTP response with no status code',
            status_code=None, request_url=request_url, response=response.text)

    message = '{who} bad response. Status code: {code} {reason}. At: {url}.'
    try:
        if response.status_code not in good_status:
            json_response = response.json()
            if not ignore_no_success or json_response.get('success'):
                try:
                    message = json_response["error"]["message"]
                except Exception:
                    message = message.format(
                        who=who, code=response.status_code,
                        reason=response.reason, url=request_url)
                raise HTTPError(
                    message, status_code=response.status_code,
                    request_url=request_url, response=response.text)
    except ValueError:
        message = message.format(
            who=who, code=response.status_code, reason=response.reason,
            url=request_url, resp=response.text[:200])
        raise HTTPError(
            message, status_code=response.status_code, request_url=request_url,
            response=response.text)


class StoringHandler(logging.Handler):
    '''A handler that stores the logging records in a database.'''
    def __init__(self, task_id, input):
        logging.Handler.__init__(self)
        self.task_id = task_id
        self.input = input

    def emit(self, record):
        conn = db.ENGINE.connect()
        try:
            # Turn strings into unicode to stop SQLAlchemy
            # "Unicode type received non-unicode bind param value" warnings.
            message = str(record.getMessage())
            level = str(record.levelname)
            module = str(record.module)
            funcName = str(record.funcName)

            conn.execute(db.LOGS_TABLE.insert().values(
                job_id=self.task_id,
                timestamp=datetime.datetime.utcnow(),
                message=message,
                level=level,
                module=module,
                funcName=funcName,
                lineno=record.lineno))
        finally:
            conn.close()


class DatetimeJsonEncoder(json.JSONEncoder):
    # Custom JSON encoder
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()

        return json.JSONEncoder.default(self, obj)


def printable_file_size(size_bytes):
    if size_bytes == 0:
        return '0 bytes'
    size_name = ('bytes', 'KB', 'MB', 'GB', 'TB')
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(float(size_bytes) / p, 1)
    return "%s %s" % (s, size_name[i])
