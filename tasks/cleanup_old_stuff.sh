#!/bin/bash

# stop puppet agent
systemctl stop puppet

while [ -f "/opt/puppetlabs/puppet/cache/state/agent_catalog_run.lock" ] ; do
        echo "puppet run currently on the way ..."
        sleep 20
done

# cleanup cron jobs
cd /etc/cron.d
rm sticky-world-writebale.cron system-file-permissions.cron unowned-files.cron  world-writebale-files.cron

# cleanup cis director
cd /usr/share/cis_security_hardening/bin
rm check_dot_files_write.sh check_home_dir_owner.sh check_netrc_files.sh check_passwd_group_exist.sh \
   check_user_home_dirs.sh root_path_integrity.sh system-file-permissions.sh  world-writable-files.sh \
   check_forward_files.sh check_home_dir_permissions.sh check_netrc_files_write.sh check_rhosts_files.sh \
   fact_upload.sh sticy-world-writable.sh unowned_files.sh

# start puppet agent
systemctl start puppet

exit 0
