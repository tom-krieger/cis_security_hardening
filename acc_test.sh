#!/bin/bash

pdk bundle -v
rm -f Gemfile.lock
pdk bundle install >/dev/null

pdk bundle exec rake 'litmus:provision_list[default]'
pdk bundle exec rake 'litmus:install_agent[puppet6]'
pdk bundle exec bolt command run 'puppet --version' -t all -i spec/fixtures/litmus_inventory.yaml
pdk bundle exec rake litmus:install_module
# pdk bundle exec bolt file upload spec/acceptance/data/cis_centos_7_rules.yaml /etc/puppetlabs/code/environments/production/modules/cis_security_hardening/data/cis/cis_centos_7_rules.yaml -t all -i spec/fixtures/litmus_inventory.yaml
# pdk bundle exec bolt file upload spec/acceptance/data/cis_centos_7_params.yaml /etc/puppetlabs/code/environments/production/modules/cis_security_hardening/data/cis/cis_centos_7_params.yaml -t all -i spec/fixtures/litmus_inventory.yaml
pdk bundle exec rake litmus:acceptance:parallel
pdk bundle exec rake 'litmus:tear_down'

exit 0
