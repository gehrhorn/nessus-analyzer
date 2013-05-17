#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'

Nessus::Parse.new("ehrhorn.nessus") do |scan|
  puts "#{scan.title} included #{ scan.hosts.count } hosts"
  puts "High severity issues #{scan.high_severity_count}"
  puts "Medium severity issue #{scan.medium_severity_count}"
  puts "Low severity issuse #{scan.low_severity_count}"
  puts "Total open ports #{scan.open_ports_count}"
end

