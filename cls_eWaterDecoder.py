"""

  cls_eWaterPayBT.py
  
  Copyright 2017  <Bostin Technology>


This class provides the comms for the Android application implementation for eWaterPay

All private functions start with _

TODO: Implement a CRC check
TODO: implement the firmware megative response command

TODO: Check all the commands meet the latest standard
- Request ID
- Firmeare File check
- Ready to receive
- Send Data Chunks
    Different response on success or failure
- When I receive a %NEW PAIRING% or other command, I need to disgard them without going any further

BUG: When writing to the file, it is adding single quotes and failing.
    

"""

import logging
import datetime
import time
import binascii

# Commands supported
CMD_ASSET_STATUS = b'A'         #0x41
CMD_REQUEST_ID = b'G'           #0x47
CMD_DATA_CHUNK = b'H'           #0x48
CMD_READY_TO_RECEIVE = b'I'     #0x49
CMD_IOT_RECEIVED_OK = b'J'      #0x4A
CMD_IOT_FIRMWARE_FAILED = bytes.fromhex('4F')       # Not yet defined

# Command Replies
RSP_POSITIVE = bytes.fromhex('80')
RSP_NEGATIVE = bytes.fromhex('11')


# Command elements
ETX_CHAR = bytes.fromhex('03')
IOT_FIRMWARE = b'\x00\x00\x01'
EWC_FIRMWARE = b'\x00\x00\x02'
EWC_BOOTLOADER = b'\x00\x00\x03'
IOT_BOOTLOADER = b'\x00\x00\x04'
POWER_ON_TIME = b'\x18\x42\x12\x12\x02\x17'
LAST_POWER_OFF_TIME = b'\x09\x30\x19\x12\x02\x17'
LAST_CHUNK_IDENTIFIER = b'\xff\xff'


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
        self.file_received = {}     # This contains a dictionary, each one being a chunk of data with the chunk number as the index
        self.file_written = False
        self.receiving_data = False
        self.response = b''                  # The reply for the calling function
        self.response_status = False        # The status of the responding message (True = Valid message to send)
        self.file_written = False
        self.chunk = b''
        self.payload = b''
        self.filename = ''        
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
        self.response = b''                  # The reply for the calling function
        self.response_status = False        # The status of the responding message (True = Valid message to send)
        self.file_written = False
        self.filename = ''

        self.message = message
        logging.debug("[EWD]: Received message for processing:%s" % self.message)
        
        if self._split_message(self.message):
            self.time_packet_received = time.time()
            if self._validated():
                logging.debug("[EWD]: Message is valid")
                if self.cmd == CMD_ASSET_STATUS:
                    logging.info("[EWD]: Asset Status Command received")
                    self.response = self._asset_response()
                    self.response_status = True
                elif self.cmd == CMD_REQUEST_ID:
                    logging.info("[EWD]: Request ID Command received")
                    self.response = self._request_id_response()
                    self.response_status = True
                elif self.cmd == CMD_READY_TO_RECEIVE:
                    logging.info("[EWD]: Ready To Receive Command received")
                    self.response = self._ready_to_receive_response()
                    self.response_status = True
                elif self.cmd == CMD_DATA_CHUNK:
                    logging.info("[EWD]: Data Chunk Command received")
                    self.response = self._process_data_chunk()
                    #self.response = self._process_firmware()
                    self.response_status = (len(self.response) > 0)     # The reply is based on data being available to send
                else:
                    # Command is unknown
                    logging.info("[EWD]: Unknown Command Received")
                    self.response_status = False  
            else:
                # Data is not valid
                logging.info("[EWD]: Message received is invalid")
                self.response_status = False  
        else:
            # Unable to Parse the data
            logging.info("[EWD]: Unable to Parse the data")
            self.response_status = False  

        return self.response

    def reply(self):
        # Return the response to send back
        return self.response
    
    def reply_status(self):
        return self.response_status

    def reply_chunk_number(self):
        return self.chunk
        
    def reply_payload(self):
        return self.payload
    
    def file_write_status(self):
        return self.file_written
    
    def return_filename(self):
        return self.filename
    
    def download_status(self):
        return self.receiving_data
    
    def exit_comms(self):
        # This routine is called to clean up any items on exit of the main program
        print("Bye!")
        
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
        if len(packet) >= MIN_LENGTH:
            # All messages longer than the minimum length have a command byte
            self.cmd = packet[CMD_LOCATION:CMD_LOCATION+1]
            if len(packet) > (MIN_LENGTH + ID_LENGTH):
                # If the message is longer than min + id, the next bit is the id
                self.pkt_id = packet[ID_START:CHUNK_COUNTER_START]
            if len(packet) > (PAYLOAD_START):
                # If the message is longer than the payload start, must contain the chunk id and the remainder of the data
                self.chunk = packet[CHUNK_COUNTER_START:PAYLOAD_START]
                if len(packet) > (PAYLOAD_START + len(ETX_CHAR)):
                    # Only add a payload if the packet is longer than the start of payload plus the etx char(s)
                    self.payload = packet[PAYLOAD_START:-LENGTH_ETX]        #Note the minus sign
            self.pkt_etx = packet[-LENGTH_ETX:]        #Note the minus sign
            status = True
        else:
            status = False
            logging.debug("[EWD]: Packet received is below the minimum length(%s)" % len(packet))
        logging.debug("[EWD]: Incoming message command:%s" % self.cmd)
        logging.debug("[EWD]: Incoming message ID:%s" % self.pkt_id)
        logging.debug("[EWD]: Incoming message Chunk Number:%s" % self.chunk)
        logging.debug("[EWD]: Incoming message Payload:%s" % self.payload)
        logging.debug("[EWD]: Incoming message ETX Character:%s" % self.pkt_etx)
        
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

    def _byte_to_bcd (byte):
        """
        Taken from eWATERtap
        """
        i=int.from_bytes(byte,"little")
        LSB=int(i/16)*10
        MSB=i-int(LSB/10)*16
        BCD=LSB+MSB
        return(BCD)


    def _bcd_to_byte(bcd):
        """
        Taken from eWATERtap
        """
        return(bytes([(int(bcd/10)*16+(bcd-int(bcd/10)*10))]))

    def _add_xor(self,packet_to_send):
        """
        Generate the XOR character
        """
        xor = 0
        for byte in (packet_to_send):
            logging.debug("byte being XOR'd:%s" % byte)
            #xor = xor ^ int(binascii.b2a_hex(byte),16)
            xor = xor ^ byte

        xor_char = binascii.a2b_hex('{:02x}'.format(xor))
        return xor_char

    def _perform_CRC_check(self):
        """
        taking the given file of data, perform a CRC check
        """
        print ("CRC Check not yet implemented")
        logging.warning("[EWD]:CRC Check not yet implemented")
        return True
    
    def _create_file(self):
        """
        Take the given file and write it to a file
        """
        self.file_written = False
        try:
            filetime = datetime.datetime.now().strftime("%y%m%d%H%M%S-%f")
            self.filename = "EWD-" + filetime + ".txt"
            datafile = open(self.filename, "w")
            for chunk,data in self.file_received.items():
                datafile.write('{0}:{1}/r/n'.format(chunk,data))
            datafile.close()
            logging.info("[EWD] - Data File Written EWD%s" % filetime)
            self.file_written = True
        except:
            # File writing failed
           logging.warning("[EWD] - Failed to write data to the log file!: %s")

        return
    
    def _firmware_received_ok(self):
        """
        Generate the firmware received ok message
        """
        packet_to_send = b''
        packet_to_send = packet_to_send + CMD_IOT_RECEIVED_OK
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        logging.info("[EWD]: Firmware Packet Received ok")
        return packet_to_send
    
    def _firmware_file_corrupt(self):
        """
        Generate the firmware failed CRC check message
        """
        packet_to_send = b''
        packet_to_send = packet_to_send + CMD_IOT_FIRMWARE_FAILED
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        logging.ingo("[EWD]: Firmware Packet Received ok")
        return packet_to_send
        
    def _asset_response(self):
        """
        Generate the Asset Response
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_ASSET_STATUS
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
        Generate a positive response to the Request for ID
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_REQUEST_ID
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR

        xor = self._add_xor(packet_to_send)
        packet_to_send = packet_to_send + xor

        logging.info("[EWD] Message TO Send: Request ID Response: %s" % packet_to_send)
        return packet_to_send

    def _ready_to_receive_response(self):
        """
        Generate a positive response to the Ready to Receive command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_READY_TO_RECEIVE
        packet_to_send = packet_to_send + ETX_CHAR

        logging.info("[EWD] Message To Send: Ready to Recieve Response: %s" % packet_to_send)
        return packet_to_send
        
    def _process_data_chunk(self):
        """
        Taking the given payload (from the _split_message function), cehck it and add it to the 
        self.file_received. If it is the end of the file, generate a file from it.
        There is no need to validate the message as the incoming stage
        Message Structure
        <CMD><ID0><ID1><ID2><ID3><Chunk MSB><Chunk LSB><byte1><byte2>..<byteN><ETX>
              self.pkt_id        self.chunk            self.payload           self.pkt_etx
        NOTE: response will be nothing unless the last chunk received
        """
        response = b''
        if self.receiving_data == False:
            logging.debug("[EWD]: Starting to receive a new file")
            # Empty the dictionary
            self.file_received = {}
            self.receiving_data = True
        # Add the data received to the dictionary
        self.file_received[self.chunk] = self.payload

        
        if self.chunk == LAST_CHUNK_IDENTIFIER:
            # We have received the last chunk of the file
            logging.info("[EWD]: Last chunk identifier received")
            if self._perform_CRC_check():
                self._create_file()
                response = self._firmware_received_ok()
                self.receiving_data = False
            else:
                logging.warning("[EWD]: CRC check of the received file failed")
                response = self._firmware_file_corrupt()
        return response

    def _process_firmware(self):
        """
        Taking the received file, split it and write it to file.
        self.message contains the incoming data
        """
        chunk = b''
        response = ''
        packet_size = 128
        msg_received = self.message
        while len(msg_received) > packet_size:
            chunk = msg_received[:packet_size]
            if self._split_message(chunk) == False:
                print("Chunk decode failed, aborting")
                print("chunk:%s" % chunk)
                sys.exit()
            response = self._process_data_chunk()
            msg_received = msg_received[packet_size:]
        return response

        
        
        
        

def main():
	
	return 0

if __name__ == '__main__':
	main()

