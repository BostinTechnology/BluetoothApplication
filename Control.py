#!/usr/bin/env python3
#
#  Control.py
#  
#  Copyright 2017  <Bostin Technology>
#  
#  This program provides
#   Configuration
#   Connectivity
#   
#  For the RN4677 Module connected to the Pi via the GPIO

import serial
import logging
import datetime
import traceback
import sys


import cls_RN4677


"""
Current status - app is running but the phone is connectting using default pin.
    - receiving of data not yet validated
    - new functions added to the class

Could be the various security settings that are wrong???


"""


def main(device):
    
    logging.info("[CTL]:Starting the main application")
    connection = [False]
    while connection[0] == False:
        try:
            # Check for connection
            print("Waiting for Bluetooth connection")
            connection = device.waiting_for_connection()
            
            # Check paired and secure
            if connection[0] == True:
                print("Device Connected")
                if connection[1] == True:
                    print("New device connection made")
            else:
                print("No connection, press any key to retry or CTRL-C to cancel")
        except KeyboardInterrupt:
            logging.debug("[CTL]: No connection made")
            print("No connection made, aborting")
            sys.exit()
    
    # Check connection
    if device.connection_status() == False:
        logging.info("[CTL]: Device connection failure")
        print("Device Connection Failure, program aborted")
        
    # Download file
    download = device.receive_data(5)
    
    # Check and save file
    print("Data downloaded:")
    print("----------------\n")
    print("%s" % download)

    # End Connection
    device.exit_comms()
    return
    
    

if __name__ == '__main__':
    
    logging.basicConfig(filename="BluetoothConfigurator.txt", filemode="w", level=logging.DEBUG,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    
    device = ""
    try:
        device = cls_RN4677.RN4677()
        main(device)
    
    except:
        if device:
            device.exit_comms()
        logging.warning("Exception:%s" % traceback.format_exc())
        print("\nError Occurred, program halted - refer to log file\n")

        

