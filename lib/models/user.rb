require 'dm-core'
require 'dm-timestamps'
require 'dm-validations'

class User
  include DataMapper::Resource
  include Sinatra::LilAuthentication::AuthenticatedSystem

  attr_accessor :password, :password_confirmation

  property :id, Serial, :protected => true
  property :email, String, :key => true, :nullable => false, :length => (5..40), :unique => true, :format => :email_address
  property :hashed_password, String
  property :salt, String, :protected => true, :nullable => false
  property :created_at, DateTime
  property :permission_level, Integer, :default => 1

  validates_present :password_confirmation, :unless => Proc.new { |t| t.hashed_password }
  validates_present :password, :unless => Proc.new { |t| t.hashed_password }
  validates_is_confirmed :password


  def get_by_email(email)
    first(:email => email) 
  end

end
