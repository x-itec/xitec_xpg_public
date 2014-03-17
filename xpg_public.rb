#!/usr/bin/env ruby
# encoding: UTF-8
#
# GPL; Boris Koester, x-itec@freenet.de, http://www.x-itec.net
# v 0.01 initial release
# +120314 code-reformat
#
require 'openssl'
require 'base64'
require 'base62'
require 'escort'

# class ExampleCommand < ::Escort::ActionCommand::Base
#
#  def global
#  end
#
#  def execute
#    Escort::Logger.output.puts "Command: #{command_name}"
#    Escort::Logger.output.puts "Options: #{options}"
#    Escort::Logger.output.puts "Command options: #{command_options}"
#    Escort::Logger.output.puts "Arguments: #{arguments}"
#    if config
#      Escort::Logger.output.puts "User config: #{config}"
#    end
#  end
# end

# this class generates the password
class PassGenerator < ::Escort::ActionCommand::Base
  def execute
    # puts "--------"
    # puts "#{command_options.password}"
    # puts "-----"
    # puts "PW: #{options[:password]}"

    size = 16 # default for webpages

    size = 256 if command_options.flag_strong

    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(command_options.password.reverse,
                                          command_options.salt.reverse,
                                          command_options.rounds, size)

    # puts key.unpack("H*")[0].to_i(16).to_s(32)
    puts key.unpack('H*')[0].to_i(16).base62_encode.reverse
  end # execute
end # class

Escort::App.create do |app|

  app.version '0.0.1'
  app.summary 'X-ITEC Password-Complexifier - public version'
  app.description "
This is an internal tool to protect services and passwords at X-itec.
You enter your name-password and a service and you get a public password.
Most people use the same password for everything - you can still do this,
but with this tool you get different passwords for every service you want
AND the password is very well designed.

This tool is no toy - its a really important utility.


  Security-Level 1 - Standard-Protection with default-params
  ----------------------------------------------------------

  xpg genpass --pass 'myname' --service 'twitter'
  xpg genpass --pass 'myname-mypass' --service 'facebook'
  xpg genpass --pass 'myname-whatever' --service 'zipfiles'

  Sample:

  xpg genpass --pass 'mysecretpassword' --service 'twitter'

  Result: 5aK6aVOn3dbzXmgOiHiTH7 (this is a new password
          scrambled more than 200.000 times)

  If you change the name of the service, the password changes, too.
  If you enter the same command again, you get the same password again.

  Copy/paste the resulting password for the website/service you use.

  Security-Level 2 - Strong passwords for special services
  -------------------------------------------------------------

  With the -x option, you create a very long and strong password
  based on your simple password.

  You can use this for VPNs, SSL-CAs, Client-Certs, GPG, OpenSSL and more.

  xpg genpass --pass 'mysecretpassword' --service 'openssl-aes' -x

  The name of the service is not a secret but keep it secure
  its a string that intializes the generator.

  The generated password from your simple pass is:

yckJYWJiprK9fAPTaUvlVMZo79XdCHqfOsADrfNVVc6wFYMoSpI7Kv5pjGndKMN6wK4jlOpSu3TAtCI
QY9788qWaeYJDUI8Cdd9GL5ucINUVvtmZMpCGGzzlHhECkLELTiLR6xAD1fMnv7ffuiC9zhhvbtELDo
9EtFUU87D2VMzfK728btNAMpEDTlRVIpc30gpWQSI4WB1AJzilj1ZGJEypIf5K7rHxbkWNXupMA6taW
qGX7aRq8VC1X1wIBYKmjxhayPkv3Ko27BGQFRYWZzTwy42L6LBBpYjKad8LfjC29zAX5omnRZSUyxhg
5Q8AtqKCMEzNbMc128qAlYojdOVW

  This is the pass that an attacker needs to figure out
if you use it for encryption.

  Now let's encrypt a file with this very long password

  openssl enc -aes-256-cbc -a -salt -in infile.txt -out outfile.enc
          -pass pass:`xpg genpass --pass 'mysecretpassword' --service 'openssl-aes' -x`

  The attacker cannot decrypt the file with 
  'mysecretpassword' he needs this tool AND your correct pass + service-name.

    Let's test the decryption without the tool to figure out if it works.

  openssl enc -d -aes-256-cbc -a -in outfile.enc -pass pass:yckJYWJiprK9fAPTaUv
lVMZo79XdCHqfOsADrfNVVc6wFYMoSpI7Kv5pjGndKMN6wK4
jlOpSu3TAtCIQY9788qWaeYJDUI8Cdd9GL5ucINUVvtmZMpC
GGzzlHhECkLELTiLR6xAD1fMnv7ffuiC9zhhvbtELDo9EtFUU
87D2VMzfK728btNAMpEDTlRVIpc30gpWQSI4WB1AJzilj1ZGJ
EypIf5K7rHxbkWNXupMA6taWqGX7aRq8VC1X1wIBYKmjxhayP
kv3Ko27BGQFRYWZzTwy42L6LBBpYjKad8LfjC29zAX5omnRZSU
yxhg5Q8AtqKCMEzNbMc128qAlYojdOVW -out decrypted.txt

  Yeah - but we just need this for decryption and your original password is still ultra secure and never used. So you are protected against dictionary-attacks, brute-force attacks and more. This password is too long and specially designed to be secure.

  openssl enc -d -aes-256-cbc -a -in outfile.enc 
          -pass pass:`xpg genpass --pass 'mysecretpassword' --service 'openssl-aes' -x` -out decrypted.txt	

REASON
------
Everybody wants your password - give them a pass, but its never the same per service and not your real password. Additionally, its protected in a way that it's not available as a dictionary pass. 


FINALLY
-------

The idea or reason for this tool is simple. Passwords are insecure but no-one wants to remember passwords for every silly site or service. So you can still use ONE password for everything you want to use AND you can use this script to use it with other security-tools / batch-operations to protect your data.

To generate ultra-strong passwords for encryption-services like openssl,openvpn, disk-encryption or other systems with 'unlimited' passwords, use -x or --strong to get a really long password thats ULTRA SECURE but too big for a typical website. 
HOW DOES THIS WORK?
-------------------
Your password is recalculated in a very complex procedure more than 200.000 times. The result is binary crap and converted into human readable form. This is not a toy, you can really rely on this tool and convert an easy password into something thats nearly unbreakable (see -x option). No one can figure out your primary password, because you need the pass AND the service name. Questions like 'he might using this or that' are now history, your pass is garbage. 

WHY?
----
Because I can?

WHO?
---
Boris Koester; http://www.x-itec.net

  "
  app.action do |options, arguments|
    #    ExampleCommand.new(options, arguments).execute
 end

 app.command :global, :aliases => :glob  do |command|
    #	puts "enter --help"
  end

app.command :genpass do |command|
    command.options do |opts|
      opts.opt :password, "Initial Password", :short => '-p', :long => '--pass', :type => :string, :default => ""
      opts.opt :salt, "Service, i. e. 'facebook,xing,github,...'", :short => '-s', :long => '--service', :type => :string, :default => "x-itec"
      opts.opt :rounds, "Birthdate, format: ttmmyyyy", :short => "-r", :long => '--rounds', :type => :integer, :default => 210375
      opts.opt :flag_strong, "STRONG - create long password for special operations", :short => '-x', :long => '--strong', :type => :boolean

   end
    command.action do |options, arguments|
     #	 ExampleCommand.new(options, arguments).execute

      PassGenerator.new(options, arguments).execute
    end
 end
end


#key = OpenSSL::PKCS5.pbkdf2_hmac_sha1("Ich bin das Kennwort und absolut supercool".reverse, "x-itec", 210375, 32)
#puts key.unpack("H*")[0].to_i(16).to_s(32)
#puts key.unpack("H*")[0].to_i(16).base62_encode.reverse
#puts key.unpack("H*").pack('H*')
