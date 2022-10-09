#!/usr/local/rbenv/shims/ruby

require 'openssl'
require 'optparse'

options = {}

option_parser = OptionParser.new do |opts|
  opts.banner = 'Usage: gen_saml_sp_x509cert.rb [options]'
  
  opts.on("--common-name CN", "Common name") do |cn|
    options[:cn] = cn
  end
  
  opts.on("--organization-unit OU", "Organization unit") do |ou|
    options[:ou] = ou
  end
  
   opts.on("--organization O", "Organization") do |o|
    options[:o] = o
  end
  
   opts.on("--country-name CN", "Country name") do |c|
    options[:c] = c
  end
  
  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end
option_parser.parse!

if options[:cn].nil? || options[:ou].nil? || options[:o].nil? || options[:c].nil?
  puts option_parser.help
  exit
end

saml_config_dir = '/srv/ontoportal/virtual_appliance/appliance_config/bioportal_web_ui/config/saml/'

# reference: https://gist.github.com/lincank/3857178
  
key = OpenSSL::PKey::RSA.new(2048)
public_key = key.public_key

open "#{saml_config_dir}sp_key.pem", 'w' do |io| io.write key.to_pem end

subject = "/C=#{options[:c]}/O=#{options[:o]}/OU=#{options[:ou]}/CN=#{options[:cn]}"

cert = OpenSSL::X509::Certificate.new
cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
cert.not_before = Time.now
cert.not_after = Time.now + 365 * 24 * 60 * 60
cert.public_key = public_key
cert.serial = 0x0
cert.version = 2

ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert
cert.extensions = [
  ef.create_extension("basicConstraints","CA:TRUE", true),
  ef.create_extension("subjectKeyIdentifier", "hash"),
  ef.create_extension("keyUsage", "cRLSign,keyCertSign", true),
]
cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                       "keyid:always,issuer:always")

cert.sign key, OpenSSL::Digest::SHA1.new

open "#{saml_config_dir}sp_cert.pem", 'w' do |io| io.write cert.to_pem end
