#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'

report_root_dir = "/data/nessus-analyzer-data/"

Dir.glob(report_root_dir+'*.nessus') do |report_file|
  Nessus::Parse.new(report_file) do |scan|
    puts "#{scan.title} included #{ scan.hosts.count } hosts"
    puts "High severity issues #{scan.high_severity_count}"
    puts "Medium severity issue #{scan.medium_severity_count}"
    puts "Low severity issuse #{scan.low_severity_count}"
    puts "Total open ports #{scan.open_ports_count}"
  end
end

