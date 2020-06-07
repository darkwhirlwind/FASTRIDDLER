import fastriddler
import fastriddler.payload_packer as pp
import pytest
import unittest

class TestArgumentParsing(unittest.TestCase):
    def test_requiredargs(self):
        '''This function tests that -j/--jmp-addr and --ip-offset are required, and sets the appropriate option'''
        with pytest.raises(SystemExit):
            pp.parse_args(['payload-packer.py']);
        with pytest.raises(SystemExit):
            pp.parse_args(['payload-packer.py','-j','0xFFFF8000'])
        with pytest.raises(SystemExit):
            pp.parse_args(['payload-packer.py','--jmp-addr','0xFFFF8000'])
        with pytest.raises(SystemExit):
            pp.parse_args(['payload-packer.py','--ip-offset','80'])
        try:
            pp.parse_args(['payload-packer.py','-j', '0xFFFF8000', '--ip-offset', '80'])
            pp.parse_args(['payload-packer.py','--jmp-addr', '0xFFFF8000', '--ip-offset', '80'])
        except SystemExit:
            self.fail("All Required Arguments cause program to exit")

    def test_jmpaddr(self):
        '''This function should test that --jmp-addr/-j <int> assigns the correct value in the opts namespace'''
        # Hex Test
        opts = pp.parse_args(['payload-packer.py','-j', '0xFFFF8000', '--ip-offset', '80']); 
        assert(opts.jmp_addr == 0xFFFF8000);
        # Int Test
        opts = pp.parse_args(['payload-packer.py','-j', '25000000', '--ip-offset', '80']); 
        assert(opts.jmp_addr == 25000000);
    def test_ipoffset(self):
        # Hex Test
        opts = pp.parse_args(['payload-packer.py','-j', '0xFFFF8000', '--ip-offset', '0x80']); 
        assert(opts.ip_offset == 0x80);
        # DEC Test
        opts = pp.parse_args(['payload-packer.py','-j', '0xFFFF8000', '--ip-offset', '80']); 
        assert(opts.ip_offset == 80);
