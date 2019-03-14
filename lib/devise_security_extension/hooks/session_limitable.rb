# After each sign in, update unique_session_id.
# This is only triggered when the user is explicitly set (with set_user)
# and on authentication. Retrieving the user from session (:fetch) does
# not trigger it.
Warden::Manager.after_set_user :except => :fetch do |record, warden, options|
  if record.respond_to?(:update_unique_session_id!) && warden.authenticated?(options[:scope])
    unique_session_id = Devise.friendly_token
    warden.session(options[:scope])['unique_session_id'] = unique_session_id
    record.update_unique_session_id!(unique_session_id)

    # Unrelated to SessionLimitable
    record.update_columns(last_user_agent: warden.request.env['HTTP_USER_AGENT'])
  end
end

# Each time a record is fetched from session we check if a new session from another
# browser was opened for the record or not, based on a unique session identifier.
# If so, the old account is logged out and redirected to the sign in page on the next request.
Warden::Manager.after_set_user :only => :fetch do |record, warden, options|
  scope = options[:scope]
  env   = warden.request.env

  if record.respond_to?(:unique_session_id) && warden.authenticated?(scope) && options[:store] != false
    if record.unique_session_id != warden.session(scope)['unique_session_id'] && !env['devise.skip_session_limitable']
      warden.raw_session.clear
      warden.logout(scope)
      record.non_unique_session!(ip_address: env['HTTP_X_FORWARDED_FOR'], user_agent: env['HTTP_USER_AGENT'])
      throw :warden, :scope => scope, :message => :session_limited
    end
  end

  # Unrelated to SessionLimitable
  if record.respond_to?(:active?) && !record.active?
    warden.raw_session.clear
    warden.logout(scope)
    throw :warden, :scope => scope, :message => I18n.t('devise.failure.user.deactivated')
  end
end
