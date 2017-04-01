#!/usr/bin/env python

import logging
import cls_eWaterDecoder

EWC_ID = b'\x01\x00\x00\x00'

def main():
    
    decode = cls_eWaterDecoder.eWaterPayAD(EWC_ID)
    decode.incoming(b'%CONNECT,9471BC5566F5,0%')
    
    decode.incoming(b'G\x03')
    
    return

if __name__ == '__main__':
    
    logging.basicConfig(filename="BluetoothConfigurator.txt", filemode="w", level=logging.DEBUG,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    main()

