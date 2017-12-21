#!/usr/bin/env ruby
require './metasm/metasm'
include Metasm

require 'pp'
require 'digest/md5'

require 'optparse'

opts = {}
OptionParser.new do |opt|
  opt.banner = 'Usage: disassemblefunc.rb [-f] <executable>'
  opt.on('-o <outfile>', '--output <outfile>', 'save the assembly listing in the specified file (defaults to stdout)') { |h| opts[:outfile] = h }
  opt.on('-graph', '--graph', 'Output is a DOT') { $GRAPH = true }
  opt.on('-svg', '--svg', 'Output is a DOT') { $SVG = true }
  opt.on('-print', '--print', 'Output is a DOT') { $PRINT = true }
end.parse!(ARGV)

target = ARGV.shift || 'bla.exe'
# the entrypoints to obfuscated functions
entrypoints = ARGV.map do |ep|
  begin
    Integer(ep)
  rescue
    ep
  end
end
entrypoints << 'entrypoint' if entrypoints.empty?

# load binary
decodedfile = AutoExe.decode_file(target)
dasm = decodedfile.disassembler
$gdasm = dasm

# disassemble obfuscated code
dasm.disassemble_fast(*entrypoints)

# Get all commited comments and functions
comments = {}
# pp renamed_functions

tbdi = []

def isStartFunction(addr)
  return 0 if $gdasm.read_raw_data(addr, 0x10).nil?
  codePatterns = ["\x8b\xff", "\x55\x8b\xec", "\x55\x89\xe5", "\xff\x25", "\xff\x15", "\x48\x83\xec", "\x48\x89\x5c\x24"]
  codePatterns.each do |patt|
    return 1 if $gdasm.read_raw_data(addr, patt.length) == patt
  end
  0
end
# dasm.decoded[0][1].instruction.cpu.init_backtrace_binding
dasm.decoded.each do |addr, _di|
  tbdi << addr
end
tbdi = tbdi.sort
tbdi.each do |addr|
  di = dasm.di_at(addr)
  comment = ''
  if di.address == entrypoints[0]
    if dasm.get_label_at(di.address)
      comment += 'Top function : ' + dasm.get_label_at(di.address) + ' '
    else
      comment += 'Top function : func_' + entrypoints[0].to_s(16) + "h_at_0x#{entrypoints[0].to_s(16)}_"
    end
  end
  comment = comments[di.address] unless comments[di.address].nil?
  if (di.opcode.name == 'call') && defined?(di.block) && !di.block.nil?
    tempargs = []
    di.block.list.each do |tempdi|
      if (tempdi.opcode.name == 'push') && (tempdi.instruction.to_s != 'push ebp')
        if (dasm.normalize(tempdi.instruction.args.last).is_a? Integer) && !dasm.decode_strz(tempdi.instruction.args.last).nil? && (dasm.decode_strz(tempdi.instruction.args.last).length > 4) && (dasm.decode_strz(tempdi.instruction.args.last) !~ /[\x80-\xff]/n)
          tempargs << 'a"' + dasm.decode_strz(tempdi.instruction.args.last).gsub(/[\x00]/n, '').gsub(/[\x0d]/n, '\\r').gsub(/[\x0a]/n, '\\n') + '"'
        elsif (dasm.normalize(tempdi.instruction.args.last).is_a? Integer) && !dasm.decode_wstrz(tempdi.instruction.args.last).nil? && (dasm.decode_wstrz(tempdi.instruction.args.last).length > 4) && (dasm.decode_wstrz(tempdi.instruction.args.last) !~ /[\x80-\xff]/n)
          tempargs << 'u"' + dasm.decode_wstrz(tempdi.instruction.args.last).gsub(/[\x00]/n, '').gsub(/[\x0d]/n, '\\r').gsub(/[\x0a]/n, '\\n') + '"'
        elsif !dasm.get_label_at(tempdi.instruction.args.last).nil?
          tempargs << dasm.get_label_at(tempdi.instruction.args.last)
        elsif (dasm.normalize(tempdi.instruction.args.last).is_a? Integer) && (isStartFunction(dasm.normalize(tempdi.instruction.args.last)) == 1)
          puts "loc_#{dasm.normalize(tempdi.instruction.args.last).to_s(16)}h_at_0x#{dasm.normalize(tempdi.instruction.args.last).to_s(16)}_"
          tempargs << "loc_#{dasm.normalize(tempdi.instruction.args.last).to_s(16)}h_at_0x#{dasm.normalize(tempdi.instruction.args.last).to_s(16)}_"
        elsif dasm.normalize(tempdi.instruction.args.last).is_a? Integer
          tempargs << '0x' + dasm.normalize(tempdi.instruction.args.last).to_s(16)
        elsif dasm.backtrace(tempdi.instruction.args.last.symbolic(tempdi), tempdi.address, origin: tempdi.address, type: :x) != []
          tempargs << dasm.backtrace(tempdi.instruction.args.last.symbolic(tempdi), tempdi.address, origin: tempdi.address, type: :x).reduce.to_s
        else
          tempargs << 'x'
        end
      end
    end
    if defined?(di.instruction.args.last.symbolic.target) && !dasm.get_label_at(di.instruction.args.last.symbolic.target.bind.reduce).nil?
      comment += " #{dasm.get_label_at(di.instruction.args.last.symbolic.target.bind.reduce)}("
    elsif defined?(di.instruction.args.last.symbolic) && (dasm.backtrace(di.instruction.args.last.symbolic(di), di.address, origin: di.address, type: :x) != [])
      comment += " #{dasm.backtrace(di.instruction.args.last.symbolic(di), di.address, origin: di.address, type: :x).reduce}("
    else
      comment += " #{di.instruction.args.last}("
    end
    tempargs = tempargs.reverse
    tempargs.each do |temparg|
      comment += temparg.to_s + ','
    end
    comment = comment[0..-2] if (comment != '') && (comment[-1] == ',')
    comment += ')'
  end
  if (dasm.normalize(di.instruction.args.last).is_a? Integer) && (di.instruction.args.length == 2)
    if (dasm.normalize(di.instruction.args.last) != 0) && /^[\x00\x09\x0a\x0d\x20-\x7d]{4}$/n =~ ((dasm.normalize(di.instruction.args.last) & 0xff).chr + ((dasm.normalize(di.instruction.args.last) & 0xff00) >> 8).chr + ((dasm.normalize(di.instruction.args.last) & 0xff0000) >> 16).chr + ((dasm.normalize(di.instruction.args.last) & 0xff000000) >> 24).chr).gsub(/[\x00]/n, ' ')
      comment += " 0x#{dasm.normalize(di.instruction.args.last).to_s(16)} = '#{((dasm.normalize(di.instruction.args.last) & 0xff).chr + ((dasm.normalize(di.instruction.args.last) & 0xff00) >> 8).chr + ((dasm.normalize(di.instruction.args.last) & 0xff0000) >> 16).chr + ((dasm.normalize(di.instruction.args.last) & 0xff000000) >> 24).chr).gsub(/[\x00]/n, ' ')}'"
    end
  end
  if dasm.normalize(di.instruction.args.last).is_a? Integer
    if !dasm.get_label_at(dasm.normalize(di.instruction.args.last)).nil? && (dasm.get_label_at(dasm.normalize(di.instruction.args.last)).to_s[0..4] != 'xref_')
      comment += " #{dasm.get_label_at(dasm.normalize(di.instruction.args.last))}" unless comment.include?(dasm.get_label_at(dasm.normalize(di.instruction.args.last)))
    elsif isStartFunction(dasm.normalize(di.instruction.args.last)) == 1
      comment += " loc_#{dasm.normalize(di.instruction.args.last).to_s(16)}h_at_0x#{dasm.normalize(di.instruction.args.last).to_s(16)}_"
    end
  end
  if defined?(di.instruction.args.last.symbolic.target)
    comment += ' ' + dasm.get_label_at(di.instruction.args.last.symbolic.target.bind.reduce).to_s if dasm.get_label_at(di.instruction.args.last.symbolic.target.bind.reduce) && !comment.include?(dasm.get_label_at(di.instruction.args.last.symbolic.target.bind.reduce).to_s)
    comment += ' ' + dasm.di_at(di.instruction.args.last.symbolic.target.bind.reduce).to_s if !dasm.di_at(di.instruction.args.last.symbolic.target).nil? && !comment.include?(dasm.di_at(di.instruction.args.last.symbolic.target.bind.reduce).to_s)
    if (dasm.normalize(di.instruction.args.last.symbolic.target).is_a? Integer) && dasm.get_section_at(dasm.normalize(di.instruction.args.last.symbolic.target)) && dasm.decode_dword(dasm.normalize(di.instruction.args.last.symbolic.target)).is_a?(Integer)
      # pp dasm.decode_dword(dasm.normalize(di.instruction.args.last.symbolic.target))
      comment += "[0x#{dasm.normalize(di.instruction.args.last.symbolic.target).to_s(16)}] -> 0x#{dasm.decode_dword(dasm.normalize(di.instruction.args.last.symbolic.target)).to_s(16)}"
    end
  elsif !dasm.get_label_at(di.instruction.args.last).nil? && dasm.get_label_at(di.instruction.args.last) =~ /^loc_/
    tramp = dasm.disassemble_instruction(di.instruction.args.last)
    if !tramp.nil? && (tramp.opcode.name == 'jmp')
      comment += ' ' + tramp.to_s if !tramp.nil? && (tramp.opcode.name == 'jmp')
      if defined?(tramp.instruction.args.last.symbolic.target)
        comment += ' -> ' + dasm.get_label_at(tramp.instruction.args.last.symbolic.target.bind.reduce).to_s if dasm.get_label_at(tramp.instruction.args.last.symbolic.target.bind.reduce)
        comment += ' -> ' + dasm.di_at(tramp.instruction.args.last.symbolic.target.bind.reduce).to_s unless dasm.di_at(tramp.instruction.args.last.symbolic.target).nil?
      end
    end
  elsif defined?(di.instruction.args.last)
    argStr = dasm.decode_strz(di.instruction.args.last)
    if !argStr.nil? && (argStr.length > 4) && (argStr !~ /([\x7f-\xff]|[\x01-\x08]|[\x0b-\x1f])/n)
      comment += 'a"' + argStr.gsub(/[\x0d]/n, '\\r').gsub(/[\x0a]/n, '\\n') + '"'
    else
      argStr = dasm.decode_wstrz(di.instruction.args.last)
      if !argStr.nil? && (argStr.length > 4) && (argStr.gsub(/[\x00]/n, '') !~ /([\x7f-\xff]|[\x01-\x08]|[\x0b-\x1f])/n)
        comment += 'u"' + argStr.gsub(/[\x00]/n, '').gsub(/[\x0d]/n, '\\r').gsub(/[\x0a]/n, '\\n') + '"'
      end
    end
  end
  di.comment = []
  di.add_comment(comment) if comment != ''
end

if opts[:outfile].nil? && $GRAPH.nil?
  tbdi.each do |addr|
    puts dasm.di_at(addr).to_s
  end
end

def parseInstr(di)
  return di.to_s.gsub('\\', '\\\\\\').gsub('"', '\\"') if $SVG.nil?
  ret = nil
  if (di.opcode.name == 'call') && (di.instruction.args.length == 1)
    if di.instruction.args.first.to_s[0..3] == 'loc_'
      ret = di.to_s.gsub('\\', '\\\\\\').gsub('"', '\\"').gsub(di.instruction.args.first.to_s, di.instruction.args.first.to_s)
    end
  end
  return di.to_s.gsub('\\', '\\\\\\').gsub('"', '\\"') if ret.nil?
  ret
end

if defined?($GRAPH) && opts[:outfile]
  File.open(opts[:outfile], 'w') do |fd|
    tbdi.each do |addr|
      di = dasm.di_at(addr)
      next unless di.opcode.name == 'call'
      tdi = dasm.di_at(di.next_addr)
      next unless defined?(tdi.block)
      tdi.block.from_normal = [] if tdi.block.from_normal.nil?
      tdi.block.from_normal << di.next_addr unless tdi.block.from_normal.include? di.address

      di.block.to_normal = [tdi.address]
    end

    fd.puts 'digraph code {'
    if defined?($PRINT)
      fd.puts '        graph [bgcolor=white];'
    else
      fd.puts '        graph [bgcolor=black];'
    end
    fd.puts '        node [color=lightgray, style=filled shape=box fontname="Courier" fontsize="8"];'
    cblock = '| '
    pdi = nil
    curblock = nil
    tbdi.each do |addr|
      di = dasm.di_at(addr)
      curblock = di.block.address if curblock.nil?

      if (di.block.list.first.address == di.address) && (!di.block.from_normal.nil? && (di.block.from_normal.length > 1))
        fd.puts '        "0x' + curblock.to_s(16) + '" [color="lightgray", label="' + cblock + '\\l"];' if cblock != ''
        cblock = '| '
        curblock = di.block.address
      end

      if !defined?(di.block) || (dasm.di_at(di.next_addr) && (di.opcode.name != 'jmp')).nil?
        cblock += parseInstr(di)
        fd.puts '        "0x' + curblock.to_s(16) + '" [color="lightgray", label="' + cblock + '\\l"];' if cblock != ''
        if (di.opcode.name == 'jmp') && !curblock.nil? && defined?(di.block.to_normal)
          di.block.to_normal.each do |dest_addr|
            fd.puts '        "0x' + curblock.to_s(16) + '" -> "0x' + dest_addr.to_s(16) + '" [color="blue"];'
          end
        end
        cblock = ''
        curblock = nil
        pdi = di
        next
      end

      if ((di.block.list.last.address == di.address) && (((!di.block.to_normal.nil? && (di.block.to_normal.length > 1)) || di.block.to_normal.nil?) || (di.opcode.name[0] == 'j') || (!dasm.di_at(di.next_addr).block.from_normal.nil? && (dasm.di_at(di.next_addr).block.from_normal.length > 1)))) || (di.opcode.name == 'jmp')
        cblock += parseInstr(di)
        cblock += '\\l| ' if di.block.list.last.address != di.address
        fd.puts '        "0x' + curblock.to_s(16) + '" [color="lightgray", label="' + cblock + '\\l"];'
        if (di.block.list.last.address == di.address) && !di.block.to_normal.nil? && (di.block.to_normal.length == 2) && (di.opcode.name != 'jmp')
          fd.puts '        "0x' + curblock.to_s(16) + '" -> "0x' + di.block.to_normal[0].to_s(16) + '" [color="green"];'
          fd.puts '        "0x' + curblock.to_s(16) + '" -> "0x' + di.block.to_normal[1].to_s(16) + '" [color="red"];'
        elsif (di.block.list.last.address == di.address) && !di.block.to_normal.nil?
          di.block.to_normal.each do |dest_addr|
            fd.puts '        "0x' + curblock.to_s(16) + '" -> "0x' + dest_addr.to_s(16) + '" [color="blue"];'
          end
        end
        curblock = nil
        cblock = '| '
      else
        cblock += parseInstr(di)
        cblock += '\\l| ' unless (di.block.list.last.address == di.address) && !dasm.di_at(di.next_addr).block.from_normal.nil? && (dasm.di_at(di.next_addr).block.from_normal.length == 1)
      end
      cblock += '\\l| ' if (di.block.list.last.address == di.address) && !dasm.di_at(di.next_addr).nil? && (!dasm.di_at(di.next_addr).block.from_normal.nil? && (dasm.di_at(di.next_addr).block.from_normal.length == 1)) && (di.opcode.name == 'call')

      pdi = di
    end
    fd.puts '}'
  end
end
