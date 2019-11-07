#!/bin/bash
#
# OntoPortal Appliance deployment wrapper for ontologies_api
# https://github.com/ncbo/ontologies_api
# Script sets up deployment environment and runs capistrano deployment job

source $(dirname "$0")/versions
COMPONENT=ontologies_api

export NCBO_BRANCH=$API_RELEASE
echo "deploying $COMPONENT from $NCBO_BRANCH branch"

# copy site config which contains customised settings for the appliance

if  [ -f  "${VIRTUAL_APPLIANCE_REPO}/appliance_config/site_config.rb" ]; then
 cp ${VIRTUAL_APPLIANCE_REPO}/appliance_config/site_config.rb ${VIRTUAL_APPLIANCE_REPO}/appliance_config/${COMPONENT}/config/environments
 echo 'copying site overides file'
fi

pushd $COMPONENT
bundle install --with development --without default --deployment --binstubs
bundle exec cap appliance deploy
popd
