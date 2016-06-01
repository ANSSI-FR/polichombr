#!/usr/bin/env ruby

require 'pp'


target = ARGV.shift
binid = ARGV.shift
datas = nil
File.open(target, 'r') { |fd|
    datas = fd.read()
}
calls = datas.scan(/\| [a-f0-9]{3,}h /)
calls = calls.sort
calls = calls.uniq
calls.each{|call_stub|
    datas = datas.gsub(call_stub,"<a xlink:href=\"javascript:displayCommBox(0x#{(call_stub.scan(/[a-f0-9]{3,}/))[0]});\">| </a>#{(call_stub.scan(/[a-f0-9]{3,}h/))[0]} ")
}
calls = datas.scan(/[0-9a-f]{3,}h call loc_[0-9a-f]{3,}h/)
calls.each{|call_stub|
    # pp "<a xlink:href=\"disassfunc.php?id_bin=#{opts[:binid]}&address=0x#{call_stub.split(' ')[0]}&view=metasmsvg\">#{call_stub}</a>"
    datas = datas.gsub(call_stub,"<a xlink:href=\"#{call_stub.split('loc_')[1].split('h')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub}</a><a xlink:href=\"javascript:displayRenameBox(0x#{(call_stub.scan(/[a-f0-9]{3,}/))[1]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
}
calls = datas.scan(/[0-9a-f]{3,}h call [a-zA-Z0-9_.-]{3,}_at_0x[a-f0-9]{3,}_/)
calls.each{|call_stub|
    datas = datas.gsub(call_stub,"<a xlink:href=\"#{call_stub.split('_at_0x')[1].split('_')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub.split('_at_0x')[0].gsub('_','_<!-- -->')}</a><a xlink:href=\"javascript:displayRenameBox(0x#{call_stub.split('_at_0x')[1].split('_')[0]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
}
calls = datas.scan(/[a-zA-Z0-9_.-]{3,}_at_0x[a-f0-9]{3,}_/)
calls.each{|call_stub|
    datas = datas.gsub(call_stub,"<a xlink:href=\"#{call_stub.split('_at_0x')[1].split('_')[0]}\" stroke-width=\"0.7\" stroke=\"blue\" fill=\"blue\">#{call_stub.split('_at_0x')[0].gsub('_','_<!-- -->')}</a><a xlink:href=\"javascript:displayRenameBox(0x#{call_stub.split('_at_0x')[1].split('_')[0]});\" stroke-width=\"0.6\" stroke=\"#80c000\" fill=\"#80c000\">[R]</a>")
}
# calls = datas.scan(/[0-9a-f]{3,}h call .{3,} iat_.{3,}/)
calls = datas.scan(/iat_[a-zA-Z0-9_.-]{3,}/)
calls = calls.sort
calls = calls.uniq
calls = calls.sort_by {|x| x.length}
calls = calls.reverse
calls.each{|call_stub|
    if call_stub.include?("_at_0x")
        
    else
        # pp "<a xlink:href=\"disassfunc.php?id_bin=#{opts[:binid]}&address=0x#{call_stub.split(' ')[0]}&view=metasmsvg\">#{call_stub}</a>"
        datas = datas.gsub(call_stub,"<a xlink:href=\"#\" stroke-width=\"0.7\" stroke=\"red\" fill=\"red\">#{call_stub.gsub('_','_<!-- -->')}</a>")
    end
}
calls = datas.scan(/\&#160;[a-zA-Z0-9_.]{3,}\([a-zA-Z0-9_".,-]{0,}\)/)
calls = calls.sort
calls = calls.uniq
calls = calls.sort_by {|x| x.length}
calls = calls.reverse
calls.each{|call_stub|
    next if 
    datas = datas.gsub(call_stub,"<a xlink:href=\"#\" stroke-width=\"0.7\" stroke=\"red\" fill=\"red\">#{call_stub.split('(')[0]}<!-- --></a>(#{call_stub.split('(')[1]}")
}
calls = datas.scan(/[au]&quot;.*&quot;/)
calls = calls.sort
calls = calls.uniq
calls = calls.sort_by {|x| x.length}
calls.each{|call_stub|
    datas = datas.gsub(call_stub,"<a xlink:href=\"#\" stroke-width=\"0.6\" stroke=\"#c00000\" fill=\"#c00000\">#{call_stub}</a>")
}

# pp datas.scan("disassfunc")
File.open(target, 'w') { |fd|
    fd.write(datas)
}
