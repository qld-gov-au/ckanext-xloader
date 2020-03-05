# encoding: utf-8

import ckan.lib.plugins as lib_plugins
import ckan.plugins as p
import ckanext.datastore.logic.schema as dsschema

get_validator = p.toolkit.get_validator

not_missing = get_validator('not_missing')
not_empty = get_validator('not_empty')
resource_id_exists = get_validator('resource_id_exists')
package_id_exists = get_validator('package_id_exists')
ignore_missing = get_validator('ignore_missing')
empty = get_validator('empty')
boolean_validator = get_validator('boolean_validator')
int_validator = get_validator('int_validator')
OneOf = get_validator('OneOf')


def xloader_submit_schema():
    schema = {
        'resource_id': [not_missing, not_empty, unicode],
        'id': [ignore_missing],
        'set_url_type': [ignore_missing, boolean_validator],
        'ignore_hash': [ignore_missing, boolean_validator],
        '__junk': [empty],
        '__before': [dsschema.rename('id', 'resource_id')]
    }
    return schema

def xloader_resource_schema(data_dict):
    if 'type' in data_dict:
        package_plugin = lib_plugins.lookup_package_plugin(data_dict['type'])
    else:
        package_plugin = lib_plugins.lookup_package_plugin()
        try:
            # use first type as default if user didn't provide type
            package_type = package_plugin.package_types()[0]
        except (AttributeError, IndexError):
            package_type = 'dataset'
            # in case a 'dataset' plugin was registered w/o fallback
            package_plugin = lib_plugins.lookup_package_plugin(package_type)
        data_dict['type'] = package_type
    schema = package_plugin.create_package_schema()['resources']
    schema.update({
        'size': []
    })
    return schema
