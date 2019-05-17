require 'devise_security_extension/hooks/expirable'

module Devise
  module Models
    # Deactivate the account after a configurable amount of time.  To be able to 
    # tell, it tracks activity about your account with the following columns:
    #
    # * last_activity_at - A timestamp updated when the user requests a page (only signed in)
    #
    # == Options
    # +:expire_after+ - Time interval to expire accounts after
    #
    # == Additions
    # Best used with two cron jobs. One for expiring accounts after inactivity, 
    # and another, that deletes accounts, which have expired for a given amount 
    # of time (for example 90 days).
    # 
    module Expirable
      extend ActiveSupport::Concern

      # Updates +last_activity_at+, called from a Warden::Manager.after_set_user hook.
      def update_last_activity!
        self.update_column(:last_activity_at, Time.now.utc)
      end

      # Tells if the account has expired
      #
      # @return [bool]
      #
      #-------------------------------------------------------------------------
      # Some major modifications here:
      #
      # 1. Replace the constant "expire_after" with a customizable value
      #    persisted in the User's associated Customer record.
      #
      # 2. If the User's "last_activity_at" column is blank (becuase the User
      #    has never confirmed their email address and actually logged in) then
      #    use the "confirmation_sent_at" column.
      #
      # 3. In either case, if the User has expired then effect a corresponding
      #    state change.
      #-------------------------------------------------------------------------
      #
      def expired?
        if self.expired_at.present?
          return self.expired_at < Time.now.utc
        end

        if self.last_activity_at.present?
          if self.last_activity_at < self.expire_after.ago

            self.lock_for_inactivity! if self.try(:can_lock_for_inactivity?)

            return true
          end

        elsif self.confirmation_sent_at.present?
          if self.confirmation_sent_at < self.expire_after.ago

            self.deactivate! if self.try(:can_deactivate?)

            return true
          end
        end

        false
      end

      # Expire an account. This is for cron jobs and manually expiring of accounts.
      #
      # @example 
      #   User.expire!
      #   User.expire! 1.week.from_now
      # @note +expired_at+ can be in the future as well
      def expire!(at = Time.now.utc)
        self.expired_at = at
        save(:validate => false)
      end

      # Overwrites active_for_authentication? from Devise::Models::Activatable
      # for verifying whether a user is active to sign in or not. If the account
      # is expired, it should never be allowed.
      #
      # @return [bool]
      def active_for_authentication?
        super && !self.expired?
      end

      # The message sym, if {#active_for_authentication?} returns +false+. E.g. needed 
      # for i18n.
      def inactive_message
        !self.expired? ? super : :expired
      end

      module ClassMethods
        ::Devise::Models.config(self, :expire_after, :delete_expired_after)

        # Sample method for daily cron to mark expired entries.
        #
        # @example You can overide this in your +resource+ model
        #   def self.mark_expired
        #     puts 'overwritten mark_expired'
        #   end
        def mark_expired
          all.each do |u|
            u.expire! if u.expired? && u.expired_at.nil?
          end
          return
        end

        # Scope method to collect all expired users since +time+ ago
        def expired_for(time = delete_expired_after)
          where('expired_at < ?', time.seconds.ago)
        end

        # Sample method for daily cron to delete all expired entries after a 
        # given amount of +time+.
        #
        # In your overwritten method you can "blank out" the object instead of 
        # deleting it.
        #
        # *Word of warning*: You have to handle the dependent method
        # on the +resource+ relations (+:destroy+ or +:nullify+) and catch this 
        # behavior (see  http://api.rubyonrails.org/classes/ActiveRecord/Associations/ClassMethods.html#label-Deleting+from+associations).
        #
        # @example 
        #   Resource.delete_all_expired_for 90.days
        # @example You can overide this in your +resource+ model
        #   def self.delete_all_expired_for(time = 90.days)
        #     puts 'overwritten delete call'
        #   end
        # @example Overwritten version to blank out the object.
        #   def self.delete_all_expired_for(time = 90.days)
        #     expired_for(time).each do |u|
        #       u.update_attributes first_name: nil, last_name: nil
        #     end
        #   end
        def delete_all_expired_for(time)
          expired_for(time).delete_all
        end

        # Version of {#delete_all_expired_for} without arguments (uses 
        # configured +delete_expired_after+ default value).
        # @see #delete_all_expired_for
        def delete_all_expired
          delete_all_expired_for(delete_expired_after)
        end
      end
    end
  end
end
