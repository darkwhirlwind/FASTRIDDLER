#!/bin/env python3
import pytest
import fastriddler
import fastriddler.payload_packer as payload_packer
def test_noarg_run() -> None:
    '''Should Display Usage'''
    with pytest.raises(SystemExit):
        payload_packer.main()
