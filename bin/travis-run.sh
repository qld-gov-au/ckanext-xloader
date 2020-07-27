#!/bin/sh -e
set -ex

flake8 --version
# stop the build if there are Python syntax errors or undefined names
flake8 . --count --select=E901,E999,F821,F822,F823 --show-source --statistics --exclude ckan,ckanext-xloader

ver=$(python -c"import sys; print(sys.version_info.major)")
if [ $ver -eq 2 ]; then
    echo "python version 2 running nosetests"
nosetests --ckan \
          --nologcapture \
          --with-pylons=subdir/test.ini \
          --with-coverage \
          --cover-package=ckanext.xloader \
          --cover-inclusive \
          --cover-erase \
          --cover-tests
elif [ $ver -eq 3 ]; then
    echo "python version 3 running pytest"
    pytest --ckan-ini=subdir/test.ini --cov=ckanext.xloader ckanext/xloader/tests
else
    echo "Unknown python version: $ver"
    exit 1
fi

# strict linting
flake8 . --count --max-complexity=27 --max-line-length=127 --statistics --exclude ckan,ckanext-xloader
