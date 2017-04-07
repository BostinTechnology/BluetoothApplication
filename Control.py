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
import cls_eWaterDecoder

EWC_ID = b'\x01\x00\x00\x00'


"""
Current status - app is running but the phone is connectting using default pin.
    - receiving of data not yet validated
    - new functions added to the class

Could be the various security settings that are wrong???

BUG: Can't use CTRL-C to exit the program
        Seen this when waiting for command


"""

def SplashScreen():
    print("***********************************************")
    print("*         Bostin Technology Emulator          *")
    print("*                                             *")
    print("*       in association with eWater Pay        *")
    print("*                                             *")
    print("*         Bluetooth Test Application           *")
    print("***********************************************\n")
    return
    
    
def main(device):
    
    decoder = cls_eWaterDecoder.eWaterPayAD(EWC_ID)
    logging.info("[CTL]:Starting the main application")
    connection = [False]
    
#   commented out as unable to pair at present
#    while connection[0] == False:
#        try:
#            # Check for connection
#            print("Waiting for Bluetooth connection")
#            connection = device.waiting_for_connection()
#            
#            # Check paired and secure
#            if connection[0] == True:
#                print("Device Connected")
#                if connection[1] == True:
#                    print("New device connection made")
#            else:
#                print("No connection, press any key to retry or CTRL-C to cancel")
#        except KeyboardInterrupt:
#            logging.debug("[CTL]: No connection made")
#            print("No connection made, aborting")
#            sys.exit()
    
    # Check connection
    if device.connection_status() == False:
        logging.info("[CTL]: Device connection failure")
        print("Device Connection Failure, program aborted")
        #sys.exit()
    
    while True:
        # Sit in a loop receiving data and processing it
        message = b''
        print("Waiting for a message")
        while len(message) < 1:
            message = device.receive_data(-1)
        print("Message Received:%s" % message)
        reply = decoder.incoming(message)
        if decoder.reply_status:
            device.send_data(reply)
            print("Reply Sent:%s" % reply)
        if decoder.download_status():
            print("Data downloading:")
        if decoder.file_write_status():
            print("File Received and stored as %s" % decoder.filename)
        
    

    # End Connection
    device.exit_comms()
    return
    
    

if __name__ == '__main__':
    
    SplashScreen()
    
    logging.basicConfig(filename="BluetoothConfigurator.txt", filemode="w", level=logging.DEBUG,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    
    device = ""
    try:
        device = cls_RN4677.RN4677()
        main(device)
    
    except:
        logging.error("[CTL]: AN error has occurred and comms is exiting")
        if device:
            device.exit_comms()
        logging.warning("Exception:%s" % traceback.format_exc())
        print("\nError Occurred, program halted - refer to log file\n")

        

