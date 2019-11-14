#!/usr/bin/env bash
# -*- mode: ruby; -*-

NIL2=\
=begin
exec env -i PATH="$(echo /{usr/{local/,},}{s,}bin | tr ' ' ':')" DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" bundle exec ruby -E BINARY:BINARY -I . -e 'load("'"$0"'");' -- "$@"
=end
nil;

require("base64");
require("open3");

require("ed25519");

# https://coolaj86.com/articles/the-openssh-private-key-format/
# https://unix.stackexchange.com/questions/466179/show-values-of-an-ed22519-private-key-stored-in-openssh-format

PROTOTYPE = [ "
6f 70 65 6e 73 73 68 2d  6b 65 79 2d 76 31 00 00
00 00 04 6e 6f 6e 65 00  00 00 04 6e 6f 6e 65 00
00 00 00 00 00 00 01 00  00 00 33 00 00 00 0b 73
73 68 2d 65 64 32 35 35  31 39 00 00 00 20 f8 7f
e3 61 bc 8f 6c 97 b6 15  ab b4 df 13 77 43 42 71
bf 70 72 ad 5a 36 68 8d  fa 2d 27 48 b3 ec 00 00
00 88 00 00 00 00 00 00  00 00 00 00 00 0b 73 73
68 2d 65 64 32 35 35 31  39 00 00 00 20 f8 7f e3
61 bc 8f 6c 97 b6 15 ab  b4 df 13 77 43 42 71 bf
70 72 ad 5a 36 68 8d fa  2d 27 48 b3 ec 00 00 00
40 6a 49 4a 5d af b8 51  00 7c 44 7b 48 03 7c 3e
f2 da 60 0f aa 15 87 4e  53 e5 76 b0 d2 c1 4d d8
eb f8 7f e3 61 bc 8f 6c  97 b6 15 ab b4 df 13 77
43 42 71 bf 70 72 ad 5a  36 68 8d fa 2d 27 48 b3
ec 00 00 00 00 01 02 03  04 05".split.join ].pack("H*");

def overpunch(bin, off, ovr)
  return (bin[0...off] + ovr + bin[(off + ovr.length)..-1]);
end

def pripub_raw(pri, pub)
  raise if (!(pub.length == 32));
  raise if (!(pri.length == 32));
  
  out = PROTOTYPE;
  out = overpunch(out, 0x3e, pub);
  out = overpunch(out, 0x7d, pub);
  out = overpunch(out, 0xa1, (pri + pub));
  
  return out;
end

def pripub(pri, pub)
  return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + Base64.encode64(pripub_raw(pri, pub)) + "-----END OPENSSH PRIVATE KEY-----\n");
end

def pinentry()
  stdout, stderr, status, = Open3.capture3("bash", "-c", "set -o xtrace ; ( echo GETPIN ; echo BYE ) | pinentry-gnome3");
  
  raise if (!(status.success?));
  
  raise if (!(stdout.lines.length == 4));
  raise if (!(stdout.lines[0] == "OK Pleased to meet you\n"));
  raise if (!(stdout.lines[1][0..1] == "D "));
  raise if (!(stdout.lines[1][-1] == "\n"));
  raise if (!(stdout.lines[2] == "OK\n"));
  
  return stdout.lines[1][2..-2];
end

def kdf(phrase)
  out = Digest::SHA256.digest(phrase);
  
  1000000.times{
    out = Digest::SHA256.digest((phrase + out));
  };
  
  return out;
end

def main()
  prikey = Ed25519::SigningKey.new(kdf(pinentry));
  pubkey = prikey.verify_key;
  
  puts(pripub(prikey.to_bytes, pubkey.to_bytes));
end

main;
