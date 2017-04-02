#!/usr/bin/env python3
"""

This application is used to test the code for the Bluetooth module.

"""

import cls_RN4677
import logging




def main():
    logging.basicConfig(filename="BluetoothTest.txt", filemode="w", level=logging.DEBUG,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    
    device = ""
    device = cls_RN4677.RN4677()
   
    return

if __name__ == '__main__':

    main()

