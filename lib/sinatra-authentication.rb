require 'sinatra/base'
require 'include/authenticated_system'

module SinatraAuthentication
  VERSION = "0.0.2"
end

module Sinatra
  module LilAuthentication

    def self.registered(app)
      #INVESTIGATE
      #the possibility of sinatra having an array of view_paths to load from
      #PROBLEM
      #sinatra 9.1.1 doesn't have multiple view capability anywhere
      #so to get around I have to do it totally manually by
      #loading the view from this path into a string and rendering it
      set :lil_authentication_view_path, File.dirname(__FILE__) + "/views/"

      #TODO write captain sinatra developer man and inform him that the documentation
      #conserning the writing of extensions is somewhat outdaded/incorrect.
      #you do not need to to do self.get/self.post when writing an extension
      #In fact, it doesn't work. You have to use the plain old sinatra DSL
      #
      # Test if User is define. isn't use User embeded
      begin
        User
        raise NotImplementedError.new('You need include Sinatra::LilAuthentication::AuthenticatedSystem in your User model') unless User.include?(Sinatra::LilAuthentication::AuthenticatedSystem)
        raise NotImplementedError.new('No self#all method in User') unless User.respond_to?(:all)
        raise NotImplementedError.new('No self#get(id) method in User') unless User.respond_to?(:get)
        raise NotImplementedError.new('No self#get_by_email(email) method in User') unless User.respond_to?(:get_by_email)
        [:id, :created_at].each do |reader_property|
          eval %{
            raise NotImplementedError.new('No reader accessor to id property in User') unless User.new.respond_to?(:#{reader_property})
          }
        end
        [:salt, :email, :hashed_password, :permission_level, :password, :password_confirmation].each do |property|
          eval %{
            raise NotImplementedError.new('No reader accessor to #{property} property in User') unless User.new.respond_to?(:#{property})
            raise NotImplementedError.new('No writer accessor to #{property} property in User') unless User.new.respond_to?(:#{property}=)
          }
        end
      rescue NameError => e
        require 'models/user'
      end

      get '/users' do
        @users = User.all
        if @users != []
          haml get_view_as_string("index.haml"), :layout => use_layout?
        else
          redirect '/signup'
        end
      end

      get '/users/:id' do
        login_required
        @user = User.get(params[:id])
        haml get_view_as_string("show.haml"), :layout => use_layout?
      end

      #convenience for ajax but maybe entirely stupid and unnecesary
      get '/logged_in' do
        if session[:user]
          "true"
        else
          "false"
        end
      end

      get '/login' do
        haml get_view_as_string("login.haml"), :layout => use_layout?
      end

      post '/login' do
        if user = User.authenticate(params[:email], params[:password])
          session[:user] = user.id
          redirect '/'
        else
          redirect '/login'
        end
      end

      get '/logout' do
        session[:user] = nil
        @message = "in case it weren't obvious, you've logged out"
        redirect '/'
      end

      get '/signup' do
        haml get_view_as_string("signup.haml"), :layout => use_layout?
      end

      post '/signup' do
        @user = User.new(params[:user])
        if @user.save
          session[:user] = @user.id
          redirect '/'
        else
          session[:flash] = "failure!"
          redirect '/'
        end
      end

      get '/users/:id/edit' do
        login_required
        redirect "/users" unless current_user.admin? || current_user == params[:id]

        @user = User.first(:id => params[:id])
        haml get_view_as_string("edit.haml"), :layout => use_layout?
      end

      post '/users/:id/edit' do
        login_required
        redirect "/users" unless current_user.admin? || current_user == params[:id]

        user = User.first(:id => params[:id])
        user_attributes = params[:user]
        if params[:user][:password] == ""
            user_attributes.delete("password")
            user_attributes.delete("password_confirmation")
        end

        if user.update_attributes(user_attributes)
          redirect "/users/#{user.id}"
        else
          throw user.errors
        end
      end

      get '/users/:id/delete' do
        login_required
        redirect "/users" unless current_user.admin? || current_user == params[:id]

        user = User.first(:id => params[:id])
        user.destroy
        session[:flash] = "way to go, you deleted a user"
        redirect '/'
      end
    end
  end

  module Helpers
    def login_required
      if session[:user]
        return true
      else
        session[:return_to] = request.fullpath
        redirect '/login'
        return false
      end
    end

    def current_user
      if session[:user]
        User.get(session[:user])
      else
        GuestUser.new
      end
    end

    def logged_in?
      !!session[:user]
    end

    def use_layout?
      !request.xhr?
    end

    #BECAUSE sinatra 9.1.1 can't load views from different paths properly
    def get_view_as_string(filename)
      view = options.lil_authentication_view_path + filename
      data = ""
      f = File.open(view, "r")
      f.each_line do |line|
        data += line
      end
      return data
    end

    def render_login_logout(html_attributes = {:class => ""})
    css_classes = html_attributes.delete(:class)
    parameters = ''
    html_attributes.each_pair do |attribute, value|
      parameters += "#{attribute}=\"#{value}\" "
    end

      result = "<div id='sinatra-authentication-login-logout' >"
      if logged_in?
        logout_parameters = html_attributes
        # a tad janky?
        logout_parameters.delete(:rel)
        result += "<a href='/users/#{current_user.id}/edit' class='#{css_classes} sinatra-authentication-edit' #{parameters}>edit account</a> "
        result += "<a href='/logout' class='#{css_classes} sinatra-authentication-logout' #{logout_parameters}>logout</a>"
      else
        result += "<a href='/signup' class='#{css_classes} sinatra-authentication-signup' #{parameters}>signup</a> "
        result += "<a href='/login' class='#{css_classes} sinatra-authentication-login' #{parameters}>login</a>"
      end

      result += "</div>"
    end
  end

  register LilAuthentication
end

class GuestUser
  def guest?
    true
  end

  def permission_level
    0
  end

  # current_user.admin? returns false. current_user.has_a_baby? returns false.
  # (which is a bit of an assumption I suppose)
  def method_missing(m, *args)
    return false
  end
end
