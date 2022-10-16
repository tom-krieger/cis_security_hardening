#!/bin/bash

VGIMAGES="vg-centos-7 vg-alma-8 vg-rocky-8"
VGIMAGES="vg-centos-7"

if [ $# -ne 1 ]
then
  prog=`basename $0`
  echo "usage: ${prog} [docker|vagrant]"
  exit 1
fi

if [ "$1" != 'docker' -a "$1" != "vagrant" ]
then
  prog=`basename $0`
  echo "usage: ${prog} [docker|vagrant]"
  exit 1
fi

pdk bundle -v
rm -f Gemfile.lock
pdk bundle install --quiet >/dev/null

case $1 in
  'docker')
    echo "=== running for $1"

    pdk bundle exec rake "litmus:provision_list[docker]"
    pdk bundle exec rake 'litmus:install_agent[puppet6]'
    pdk bundle exec bolt command run 'puppet --version' -t all -i spec/fixtures/litmus_inventory.yaml
    pdk bundle exec rake litmus:install_module
    pdk bundle exec bolt command run 'puppet module list' -t all -i spec/fixtures/litmus_inventory.yaml
    echo "=== applying module"
    pdk bundle exec rake litmus:acceptance:parallel
    pdk bundle exec rake 'litmus:tear_down'
    ;;

  'vagrant')
    echo "=== running for $1"

    for vgi in $VGIMAGES ; do
      echo "=== deploying image $vgi"

      pdk bundle exec rake "litmus:provision_list[$vgi]"
      pdk bundle exec rake 'litmus:install_agent[puppet6]'
      pdk bundle exec bolt command run 'puppet --version' -t all -i spec/fixtures/litmus_inventory.yaml
      pdk bundle exec rake litmus:install_module
      pdk bundle exec bolt command run 'puppet module list' -t all -i spec/fixtures/litmus_inventory.yaml
      if [ "$vgi" = "vg-centos-7" ]
      then
        pdk bundle exec bolt file upload spec/acceptance/data/vagrant/cis_centos_7_params.yaml /etc/puppetlabs/code/environments/production/modules/cis_security_hardening/data/cis/cis_centos_7_params.yaml -t all -i spec/fixtures/litmus_inventory.yaml
      fi
      echo "=== applying module"
      pdk bundle exec rake litmus:acceptance:parallel
      pdk bundle exec rake litmus:acceptance:parallel
      pdk bundle exec rake litmus:acceptance:parallel
      # run tests with more output
      # TARGET_HOST=localhost:2222 pdk bundle exec rspec ./spec/acceptance --format d
      # TARGET_HOST=localhost:2223 pdk bundle exec rspec ./spec/acceptance --format d
      pdk bundle exec rake 'litmus:tear_down'
      
    done
    ;;
  *)
    echo "no clue what to do: $1"
    exit 2
    ;;
esac

# pdk bundle exec bolt file upload spec/acceptance/data/cis_centos_7_rules.yaml /etc/puppetlabs/code/environments/production/modules/cis_security_hardening/data/cis/cis_centos_7_rules.yaml -t all -i spec/fixtures/litmus_inventory.yaml
# pdk bundle exec bolt file upload spec/acceptance/data/cis_centos_7_params.yaml /etc/puppetlabs/code/environments/production/modules/cis_security_hardening/data/cis/cis_centos_7_params.yaml -t all -i spec/fixtures/litmus_inventory.yaml

exit 0
