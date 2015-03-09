#!/usr/bin/env python
# encoding: utf-8
'''
parser.ControlFlow -- shortdesc

parser.ControlFlow is a description

It defines classes_and_methods

@author:     beebs-systap

@copyright:  2015 SYSTAP, LLC. All rights reserved.

@license:    Apache2

@contact:    @beebs-systap
@deffield    created:  2015-03-08
'''

from compiler.misc import Stack
from optparse import OptionParser
import os
from scipy.io.matlab.mio5_utils import np
import sys

from pandas.core.index import MultiIndex

import pandas as pd


__all__ = []
__version__ = 0.1
__date__ = '2015-03-08'
__updated__ = '2015-03-08'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

def convertToInt(addr):
    return int(addr,0), addr

def incrementHexStr(addr):  
    int_val = int(addr,0)
    int_val += 1
    return '0x' + hex(int_val)[2:].rjust(16, '0')

def generateTTLHeader():
    header = "#baseURI:       http://www.systap.com/data/control_flow#\n" 
    header += "@prefix owl:     <http://www.w3.org/2002/07/owl#> .\n" 
    header += "@prefix rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n" 
    header += "@prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#> .\n" 
    header += "@prefix xsd:     <http://www.w3.org/2001/XMLSchema#> .\n" 
    header += "@prefix ctl:     <http://www.systap.com/data/control_flow#> .\n" 
    
    return header

def generateTTLForInstruction(src_addr,dest_addr,flow_type,sequence,return_addr,next_ins_addr):
    
    ttl_str = getURIForInstruction(src_addr,dest_addr,flow_type) + "\n"
    ttl_str += "\trdfs:label \" src: {0},  dest: {1} ".format(src_addr,dest_addr) 
    ttl_str += " , type: " + getPredicateForFlowType(flow_type) + "\" ;\n"
    ttl_str +="\tctl:srcAddress " + getURIForAddress(src_addr) + " ;\n"
    ttl_str +="\tctl:destAddress " + getURIForAddress(dest_addr) + " ;\n"
    ttl_str += "\t"+getPredicateForFlowType(flow_type)+" "+ getURIForAddress(dest_addr)  + " ;\n"
    ttl_str += "\tctl:returnAddress " + getURIForAddress(return_addr) + " ;\n"
    
    if next_ins_addr is not None:
        ttl_str += "\tctl:nextInstruction " + getURIForAddress(next_ins_addr) + " ;\n"
        
    ttl_str += "\txsd:integer {0} . \n ".format(sequence)
    
    return ttl_str
    
    
def getURIForInstruction(src_addr,dest_addr,flow_type):
    return "<ctl:{0}_{1}_{2}>".format(src_addr, dest_addr, flow_type)

def getURIForAddress(addr):
    return "<ctl:{0}>".format(addr)

def getPredicateForFlowType(flow_type):
    #  C - direct call
    #  c  - indirect call
    #  s  - system call
    #  r  - return
    #  B - direct branch
    #  b  - indirect branch
  
    return { 
            'C' : "ctl:directCall",
            'c' : "ctl:indirectCall",
            's' : "ctl:systemCall",
            'r' : "ctl:return",
            'B' : "ctl:directBranch",
            'b' : "ctl:indirectBranch",
            }.get(flow_type,"ctl:controlFlow")

def parseControlFlowTTL (infile):
    
    csvfile = open(infile,'r')

    ctl_flow = pd.read_csv(csvfile, delim_whitespace=True)

    sorted_ctl_flow = ctl_flow.sort('src')
    
    sorted_ctl_flow.set_index(['src'],inplace=True)
   
    if DEBUG: 
        print sorted_ctl_flow
        
    if DEBUG:
        print sorted_ctl_flow.xs("0x00007fff8cb70e4d")

    ins_cnt = 0
    
    #max_addr = sorted_ctl_flow[ctl_flow.xs(max_elements-1)[0]][0]
    #FIXME:  Update to get actual max from the DataFrame

    max_addr = int("0xFFFFFFFFFFFFFFFF",0)
    
    print generateTTLHeader()

    for instruction in ctl_flow.iterrows():
        #sys.stderr.write("Processing {0} of {1}:  ".format(ins_cnt, max_elements))
        start_addr = instruction[1][0]

        end_addr = instruction[1][1]
        flowtype = instruction[1][2]
        sequence = instruction[1][3]
        return_addr = instruction[1][4]
        if DEBUG:
            print '{0} {1} {2} {3} {4}'.format(start_addr, end_addr, flowtype, sequence, return_addr)

        next_ins_addr = None
        #We have a call and need to find the address present in the file.
        if flowtype == 'C':
            next_ins_addr = findNextCallFromReturn(sorted_ctl_flow, max_addr, return_addr)
        
        print generateTTLForInstruction(start_addr, end_addr, flowtype, sequence, return_addr, next_ins_addr)

        ins_cnt+=1 

def parseControlFlow (infile):
    
    csvfile = open(infile,'r')

    ctl_flow = pd.read_csv(csvfile, delim_whitespace=True)

    sorted_ctl_flow = ctl_flow.sort('src')
    
    sorted_ctl_flow.set_index(['src'],inplace=True)
   
    if DEBUG: 
        print sorted_ctl_flow
        
    if DEBUG:
        print sorted_ctl_flow.xs("0x00007fff8cb70e4d")

    ins_cnt = 0
    max_elements = len(ctl_flow.index)

    #max_addr = sorted_ctl_flow[ctl_flow.xs(max_elements-1)[0]][0]
    #FIXME:  Update to get actual max from the DataFrame

    max_addr = int("0xFFFFFFFFFFFFFFFF",0)
    

    current_Call = None
    call_stack = []
    call_buffer_str = ""

    for instruction in ctl_flow.iterrows():
        #sys.stderr.write("Processing {0} of {1}:  ".format(ins_cnt, max_elements))
        start_addr = instruction[1][0]

        end_addr = instruction[1][1]
        flowtype = instruction[1][2]
        sequence = instruction[1][3]
        return_addr = instruction[1][4]
        if DEBUG:
            print '{0} {1} {2} {3} {4}'.format(start_addr, end_addr, flowtype, sequence, return_addr)

        #We have a call and need to find the address present in the file.
        if flowtype == 'C':
            next_ins_addr = findNextCallFromReturn(sorted_ctl_flow, max_addr, return_addr)
            #print '{0} {1} {2} {3} {4} {5}'.format(start_addr, end_addr, flowtype, sequence, return_addr, next_ins_addr)
            stack_peek = None
          
            
            if call_stack is not None and len(call_stack) > 0:
                stack_peek = call_stack.pop()
                
            if DEBUG:
                sys.stderr.write('{0} {1}\n'.format(next_ins_addr, stack_peek))

            print 'Stack length is {0}'.format(len(call_stack))

            if next_ins_addr == stack_peek:
                #call_buffer_str+=", "+next_ins_addr+"\n"
                call_buffer_str+=", "
                if DEBUG:
                    sys.stderr.write('Popped {0}'.format(next_ins_addr))
                print call_buffer_str
                call_buffer_str = ""
            else: 
                if stack_peek is not None:
                    call_stack.append(stack_peek)
            
            if call_stack is not None and len(call_stack) > 0:
                call_buffer_str+=', {0} {1}'.format(start_addr, flowtype)
            else:
                print call_buffer_str
                call_buffer_str = ""
                call_buffer_str+='\n{0} {1}'.format(start_addr,flowtype)

            current_Call = start_addr+"_"+end_addr+"_"+flowtype
            call_stack.append(next_ins_addr)
            if DEBUG:
                sys.stderr.write('Pushed {0}'.format(next_ins_addr))
        else:
            #print '{0} {1} {2} {3} {4}'.format(start_addr, end_addr, flowtype, sequence, return_addr)
            call_buffer_str+=','+start_addr+" "+flowtype

        ins_cnt+=1 
        
    #The control flow returns omit system calls.  Not all memory addresses
    #will be present in the flow file.  We need to find the first address that exists
    #greater than the return address from the call.    
def findNextCallFromReturn(flow_array, max_addr, return_addr):

    next_ins_addr = None
    working_ins_addr = return_addr
    max_elements = max_addr

    #while next_ins_addr == -1 and working_ins_addr < max_elements:
    while next_ins_addr is None and int(working_ins_addr,0) < max_elements:
        if DEBUG:
            print working_ins_addr
        try:
            row = flow_array.xs(working_ins_addr)
            next_ins_addr = working_ins_addr
        except Exception, e:
            working_ins_addr = incrementHexStr(working_ins_addr)
            if DEBUG:
                print 'Working address now {0}'.format(working_ins_addr)
    
    if next_ins_addr is None:
        sys.stderr.write("No address found for {0}".format(return_addr))    
    
    return next_ins_addr
        
def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"
    program_build_date = "%s" % __updated__

    program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
    #program_usage = '''usage: spam two eggs''' # optional - will be autogenerated by optparse
    program_longdesc = '''''' # optional - give further explanation about what the program does
    program_license = "Copyright 2015 beebs-systap (SYSTAP, LLC)                                            \
                Licensed under the Apache License 2.0\nhttp://www.apache.org/licenses/LICENSE-2.0"


    if argv is None:
        argv = sys.argv[1:]
    try:
        # setup option parser
        parser = OptionParser(version=program_version_string, epilog=program_longdesc, description=program_license)
        parser.add_option("-i", "--in", dest="infile", help="set input path [default: %default]", metavar="FILE")
        parser.add_option("-o", "--out", dest="outfile", help="set output path [default: %default]", metavar="FILE")
        parser.add_option("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %default]")

        # process options
        (opts, args) = parser.parse_args(argv)
        
        infile = sys.stdin
        outfile = sys.stdout

        if opts.verbose > 0:
            sys.stderr.write("verbosity level = %d" % opts.verbose)

        if opts.infile:
            sys.stderr.write("infile = %s" % opts.infile)
            infile = opts.infile
        else:
            #print("Assuming stdin.")
            opts.infile='data/flowcon.out'

        if opts.outfile:
            sys.stderr.write("outfile = %s" % opts.outfile)
            outfile = opts.outfile
        else:
            sys.stderr.write("Assuming stdout.")

        # MAIN BODY #
        
        sys.stderr.write('Loading %s' % opts.infile)
        
        parseControlFlowTTL(opts.infile)

    except Exception, e:
        sys.stderr.write(repr(e))
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2


if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-v")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'parser.ControlFlow_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
