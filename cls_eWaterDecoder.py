"""

  cls_eWaterPayBT.py
  
  Copyright 2017  <Bostin Technology>


This class provides the comms for the Android application implementation for eWaterPay

All private functions start with _


"""

import logging
import datetime
import time

# Commands supported
CMD_ASSET_STATUS = b'A'         #0x41
CMD_REQUEST_ID = b'G'           #0x47
CMD_DATA_CHUNK = b'H'           #0x48
CMD_READY_TO_RECEIVE = b'I'     #0x49
CMD_IOT_RECEIVED_OK = b'J'      #0x4A

# Command Replies
RSP_POSITIVE = bytes.fromhex('80')
RSP_NEGATIVE = bytes.fromhex('11')
ETX_CHAR = bytes.fromhex('03')


# Command elements
ETX_CHAR = b'\x03'
IOT_FIRMWARE = b'V1.11'
EWC_FIRMWARE = b'V2.22'
EWC_BOOTLOADER = b'V3.33'
IOT_BOOTLOADER = b'V4.44'
POWER_ON_TIME = b'12:12:12'
LAST_POWER_OFF_TIME = b'11:11:11'

# Pointers to message parts (all starting from zero)
CMD_LOCATION = 0
ID_START = 1
CHUNK_COUNTER_START = 5
PAYLOAD_START = 7


# Other parameters
MIN_LENGTH = 2          # What is the shortest valid message to be processed
ID_LENGTH = 4           # The number of bytes for the ID
CHUNK_COUNTER_LEN = 2   # The length of the chunk counter
LENGTH_ETX = 1          # The length of the ETX character(s)




class eWaterPayAD:
    """
    Class to handle the comms with the Android Application
    
    """
    def __init__(self, ewc):
        """
        Initilisation for the comms
        """
        self.ewc = ewc              # The ID of the EWC
        self.cmd= b''

        return

    def incoming(self, message):
        """
        Decode the received message and return the reply
        
        """
        #Clear the contents of the message elements
        self.pkt_id = b''
        self.cmd = b''
        self.chunk = b''
        self.payload = b''
        self.pkt_etx = b''
        self.response = b''
        self.response_status = False

        self.message = message
        logging.debug("[EWD]: Received message for processing:%s" % self.message)
        
        if self._split_message(self.message):
            self.time_packet_received = time.time()
            if self._validated():
                logging.debug("[EWD]: Message is valid")
                if self.cmd == ASSET_STATUS:
                    logging.info("[EWD]: Asset Status Command received")
                    self.response = self._asset_response()
                    self.response_status = True
                elif self.cmd == REQUEST_ID:
                    logging.info("[EWD]: Request ID Command received")
                    self.response = self._request_id_response()
                    self.response_status = True
                elif self.cmd == READY_TO_RECEIVE:
                    logging.info("[EWD]: Ready To Receive Command received")
                    self.response = self._ready_to_receive_response()
                    self.response_status = True
                elif self.cmd == DATA_CHUNK:
                    logging.info("[EWD]: Data Chunk Command received")
                    self.response = self._data_chunk_response()
                    self.response_status = True
                else:
                    # Data is not valid
                    logging.info("[EWD]: Unknown Command Received")
                    self.response = self._generate_nack()
                    self.response_status = True  
        
        #TODO: What do I do here?????


        return

#-----------------------------------------------------------------------
#
#    P R I V A T E   F U N C T I O N S
#
#-----------------------------------------------------------------------

    def _split_message(self,packet):
        """
        Splits the packet into the constituant parts
        """
        status = False
        if len(packet) > MIN_LENGTH:
            # All messages longer than the minimum length have a command byte
            self.cmd = packet[CMD_LOCATION]
            if len(packet) > (MIN_LENGTH + ID_LENGTH):
                # If the message is longer than min + id, the next bit is the id
                self.pkt_id = packet[ID_START:CHUNK_COUNTER_START]
            if len(packet) > (PAYLOAD_START):
                # If the message is longer than the payload start, must contain the reaminder of the data
                self.chunk = packet[CHUNK_COUNTER_START:PAYLOAD_START]
                self.payload = packet[PAYLOAD_START:-LENGTH_ETX]        #Note the minus sign
            self.pkt_etx = packet[-LENGTH_ETX:]         #Note the minus sign
            status = True
        else:
        logging.debug("[EWD]: Incoming message command:%s" % self.cmd)
        logging.debug("[EWD]: Incoming message ID:%s" % self.pkt_id)
        logging.debug("[EWD]: Incoming message Chunk Number:%s" % self.chunk)
        logging.debug("[EWD]: Incoming message Payload:%s" % self.payload)
        return status

    def _validated(self):
        # Routine to check the incoming packet is valid and for this instance of the EWC
        if len(self.pkt_id) > 0:
            if self.ewc != self.pkt_id:
                logging.info("[EWD]: Message Validation: Incorrect ID")
                return False
        if self.pkt_etx != ETX_CHAR:
            logging.info("[EWD]: Message Validation: Missing ETX Character(s)")
            return False
        
        return True

    def _add_xor(packet_to_send):
        """
        Generate the XOR character
        """
        xor = 0
        for byte in (packet_to_send):
            logging.debug("byte being XOR'd:%s" % byte)
            xor = xor ^ int(binascii.b2a_hex(byte),16)

        xor_char = binascii.a2b_hex('{:02x}'.format(xor))
        return xor_char

    def _asset_response(self):
        """
        Generate the Asset Response
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + POSITIVE_CMD
        packet_to_send = packet_to_send + IOT_FIRMWARE
        packet_to_send = packet_to_send + EWC_FIRMWARE
        packet_to_send = packet_to_send + EWC_BOOTLOADER
        packet_to_send = packet_to_send + IOT_BOOTLOADER
        packet_to_send = packet_to_send + POWER_ON_TIME
        packet_to_send = packet_to_send + LAST_POWER_OFF_TIME
        packet_to_send = packet_to_send + ETX_CHAR

        xor = self._add_xor(packet_to_send)
        packet_to_send = packet_to_send + xor

        logging.info("[EWD] Message TO Send: Asset Status Response: %s" % packet_to_send)
        return packet_to_send

    def _request_id_response(self):
        """
        
        """
        packet_to_send = b''

        print ("Not yet implemented")

        return response

    def _ready_to_receive_response(self):
        """
        
        """
        packet_to_send = b''

        print ("Not yet implemented")

        return response

    def _data_chunk_response(self):
        """
        
        """
        packet_to_send = b''

        print ("Not yet implemented")

        return response

        

def main():
	
	return 0

if __name__ == '__main__':
	main()

