#!/usr/bin/env ruby

require 'pp'

target = ARGV.shift
datas = nil

def parse_calls(datas, regexp)
  calls = datas.scan(regexp)
  calls.sort
  calls.uniq
end

File.open(target, 'r') do |fd|
  datas = fd.read
end

calls = datas.scan(/[0-9a-f]{3,}h call loc_[0-9a-f]{3,}h/)
calls.each do |call_stub|
  datas = datas.gsub(call_stub, "<a xlink:href=\"#{call_stub.split('loc_')[1].split('h')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub}</a><a xlink:href=\"javascript:displayRenameBox(0x#{(call_stub.scan(/[a-f0-9]{3,}/))[1]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
end

calls = datas.scan(/[0-9a-f]{3,}h call [a-zA-Z0-9_.-]{3,}_at_0x[a-f0-9]{3,}_/)
calls.each do |call_stub|
  datas = datas.gsub(call_stub, "<a xlink:href=\"#{call_stub.split('_at_0x')[1].split('_')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub.split('_at_0x')[0].gsub('_','_<!-- -->')}</a><a xlink:href=\"javascript:displayRenameBox(0x#{call_stub.split('_at_0x')[1].split('_')[0]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
end

calls = datas.scan(/[a-zA-Z0-9_.-]{3,}_at_0x[a-f0-9]{3,}_/)
calls.each do |call_stub|
  datas = datas.gsub(call_stub, "<a xlink:href=\"#{call_stub.split('_at_0x')[1].split('_')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub.split('_at_0x')[0].gsub('_','_<!-- -->')}</a><a xlink:href=\"javascript:displayRenameBox(0x#{call_stub.split('_at_0x')[1].split('_')[0]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
end

calls = parse_calls(datas, /iat_[a-zA-Z0-9_.-]{3,}/)
calls = calls.sort_by { :length }
calls = calls.reverse
calls.each do |call_stub|
  if call_stub.include?('_at_0x')

  else
    datas = datas.gsub(call_stub, "<a xlink:href=\"#\" stroke-width=\"0.7\" stroke=\"red\" fill=\"red\">#{call_stub.gsub('_', '_<!-- -->')}</a>")
  end
end

calls = parse_calls(datas, /\&#160;[a-zA-Z0-9_.]{3,}\([a-zA-Z0-9_".,-]{0,}\)/)
calls = calls.sort_by { :length }
calls = calls.reverse
calls.each do |call_stub|
  next if
  datas = datas.gsub(call_stub, "<a xlink:href=\"#\" stroke-width=\"0.7\" stroke=\"red\" fill=\"red\">#{call_stub.split('(')[0]}<!-- --></a>(#{call_stub.split('(')[1]}")
end

calls = parse_calls(datas, /[au]&quot;.*&quot;/)
calls = calls.sort_by { :length }
calls.each do |call_stub|
  datas = datas.gsub(call_stub, "<a xlink:href=\"#\" stroke-width=\"0.6\" stroke=\"#c00000\" fill=\"#c00000\">#{call_stub}</a>")
end

File.open(target, 'w') do |fd|
  fd.write(datas)
end
