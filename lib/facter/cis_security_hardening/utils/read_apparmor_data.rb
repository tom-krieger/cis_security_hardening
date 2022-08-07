# frozen_string_literal: true

def read_apparmor_data
  apparmor = {}
  if File.exist?('/sbin/apparmor_status') || File.exist?('/usr/sbin/apparmor_status')
    val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are loaded"')
    apparmor['profiles'] = if val.nil? || val.empty?
                             0
                           else
                             val.match(%r{(?<profiles>\d+) profiles are loaded})['profiles']
                           end
    val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are in enforce mode"')
    apparmor['profiles_enforced'] = if val.nil? || val.empty?
                                      0
                                    else
                                      val.match(%r{(?<enforce>\d+) profiles are in enforce mode})[:enforce]
                                    end
    val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are in complain mode"')
    apparmor['profiles_complain'] = if val.nil? || val.empty?
                                      0
                                    else
                                      val.match(%r{(?<complain>\d+) profiles are in complain mode})[:complain]
                                    end
    val = Facter::Core::Execution.exec('apparmor_status | grep "processes are unconfined but have a profile defined"')
    apparmor['processes_unconfined'] = if val.nil? || val.empty?
                                         0
                                       else
                                         val.match(%r{(?<complain>\d+) processes are unconfined but have a profile defined})[:complain]
                                       end
    apparmor['profiles_status'] = (apparmor['profiles'].to_i - apparmor['profiles_enforced'].to_i - apparmor['profiles_complain'].to_i).zero?
  end

  apparmor
end
