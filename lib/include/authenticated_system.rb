p 'include'
module Sinatra
  module LilAuthentication
    module AuthenticatedSystem

      attr_accessor :password, :password_confirmation

      def self.included(base)
        base.extend ClassMethods
      end

      def password=(pass)
        @password = pass
        self.salt = self.class.random_string(10) if !self.salt
        self.hashed_password = self.class.encrypt(@password, self.salt)
      end

      def admin?
        self.permission_level == -1 || self.id == 1
      end

      module ClassMethods
        def authenticate(email, pass)
          current_user = self.get_by_email(email)
          return nil if current_user.nil?
          return current_user if self.encrypt(pass, current_user.salt) == current_user.hashed_password
          nil
        end  

        def random_string(len)
          #generate a random password consisting of strings and digits
          chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
          newpass = ""
          1.upto(len) { |i| newpass << chars[rand(chars.size-1)] }
          return newpass
        end

        def encrypt(pass, salt)
          Digest::SHA1.hexdigest(pass+salt)
        end
      end

    end
  end
end
