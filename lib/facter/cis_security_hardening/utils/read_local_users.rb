# frozen_string_literal: true

def read_local_users
  local_users = {}
  user_list = Facter::Core::Execution.exec('egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1').split("\n")
  user_list.each do |user|
    local_users[user] = {}

    # parse chage output for each user in /etc/shadow and create variables
    last_password_change   = %r{:\s*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Last password\"")).to_s
    password_expires       = %r{:\s*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Password expires\"")).to_s
    password_inactive      = %r{:\s*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Password inactive\"")).to_s
    account_expires        = %r{:\s*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Account expires\"")).to_s
    minimum_number_of_days = %r{:\d*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Minimum\""))[0].to_i
    maximum_number_of_days = %r{:\d*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"Maximum\""))[0].to_i
    warning_number_of_days = %r{:\d*\K.*}.match(Facter::Core::Execution.exec("chage --list #{user} | grep \"warning\""))[0].to_i

    # set default values for facts
    last_password_change_days = last_password_change
    password_expires_days     = password_expires
    password_inactive_days    = password_inactive
    account_expires_days      = account_expires

    # check if password attribute not 'never' or 'password must be changed', then determine days between now and then
    # and check if password is set prior to current date
    unless ['never', 'password must be changed'].include?(last_password_change)
      last_password_change_days = (Date.today - Date.parse(last_password_change)).to_i
      password_date_valid       = Date.parse(last_password_change) <= Date.today
    end

    unless ['never', 'password must be changed'].include?(password_expires)
      password_expires_days = (Date.parse(password_expires) - Date.today).to_i

      unless ['never', 'password must be changed'].include?(password_inactive)
        password_inactive_days = (Date.parse(password_inactive) - Date.parse(password_expires)).to_i
      end
    end

    unless account_expires == 'never'
      account_expires_days = (Date.parse(account_expires) - Date.today).to_i
    end

    # create nested fact
    local_users[user] = {
      'last_password_change_days'         => last_password_change_days,
      'password_expires_days'             => password_expires_days,
      'password_inactive_days'            => password_inactive_days,
      'account_expires_days'              => account_expires_days,
      'min_days_between_password_change'  => minimum_number_of_days,
      'max_days_between_password_change'  => maximum_number_of_days,
      'warn_days_between_password_change' => warning_number_of_days,
      'password_date_valid'               => password_date_valid,
    }
  end
  local_users
end
