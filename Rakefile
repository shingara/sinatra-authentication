require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new('sinatra-authentication', '0.0.2') do |p|
  p.description    = "Simple authentication plugin for sinatra."
  p.url            = "http://github.com/maxjustus/sinatra-authentication"
  p.author         = "Max Justus Spransy"
  p.email          = "maxjustus@gmail.com"
  p.ignore_pattern = []
  p.development_dependencies = ["sinatra"]

end

Dir["#{File.dirname(__FILE__)}/tasks/*.rake"].sort.each { |ext| load ext }
