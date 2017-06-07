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
import random

# Commands supported
CMD_ASSET_STATUS = b'A'         #0x41
CMD_REQUEST_ID = b'G'           #0x47
CMD_DATA_CHUNK = b'H'           #0x48
CMD_READY_TO_RECEIVE = b'I'     #0x49
CMD_LAST_RECORD_PTR = b'L'      #0x4C
CMD_MISSING_DATALOG_REQ = b'R'  #0x52
CMD_DATALOG_PACKET = b'D'       #0x44
CMD_SET_RTC = b'C'              #0x43
CMD_VALVE_ON = b'V'             #0x56

# Command Replies
RSP_POSITIVE = bytes.fromhex('80')
RSP_NEGATIVE = bytes.fromhex('11')
RSP_XOR_FAILURE = bytes.fromhex('88')
RSP_NOT_READY = bytes.fromhex('14')
RSP_COMMS_ERROR = bytes.fromhex('16')
RSP_DEVICE_BUSY = bytes.fromhex('17')
RSP_FIRMEWARE_OK = b'J'



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
CHUNK_LEN_POSN = 7
CHUNK_COUNTER_START = 5
PAYLOAD_START = 8
BLOCK_POSN = 5
POINTER_START = 6


# Other parameters
MIN_LENGTH = 2          # What is the shortest valid message to be processed
ID_LENGTH = 4           # The number of bytes for the ID
CHUNK_COUNTER_LEN = 2   # The length of the chunk counter
LENGTH_ETX = 1          # The length of the ETX character(s)

# Default valeus for the returned data packet
UUID = b'\x3e\xAA\xAA\x3c'
USAGE = b'\x30\x30\x31\x31'
START_CREDIT = b'\x34\x30\x30\x30'
END_CREDIT = b'\x33\x39\x38\x39'
FLOW_COUNT = b'\x01\x10'
FLOW_TIME = b'\x1A\x1A'
LITRE_CREDIT_CONV = b'\xC1\xC0'


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
        self.len_chunk = b''
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
        self.len_chunk = b''
        self.payload = b''
        self.pkt_etx = b''
        self.response = b''                  # The reply for the calling function
        self.response_status = False        # The status of the responding message (True = Valid message to send)
        self.file_written = False
        self.filename = ''

        self.message = message
        logging.debug("[EWD]: Received message for processing:%s" % self.message)
        
        if self._extract_parts(self.message):
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
                    self.response_status = True
                elif self.cmd == CMD_LAST_RECORD_PTR:
                    logging.info("[EWD]: Last Record Pointer Request received")
                    self.response = self._last_record_pointer()
                    self.response_status = True
                elif self.cmd == CMD_MISSING_DATALOG_REQ:
                    logging.info("[EWD]: Missing Datalog Record Request received")
                    self.response = self._missing_datalog_record()
                    self.response_status = True
                elif self.cmd == CMD_SET_RTC:
                    logging.info("[EWD]: Set RTC ID Command received")
                    self.response = self._set_rtc_response()
                    self.response_status = True
                elif self.cmd == CMD_VALVE_ON:
                    logging.info("[EWD]: Valve On Command received")
                    self.response = self._valve_on_response()
                    self.response_status = True
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

    def _extract_parts(self,packet):
        """
        Extracts the cmd byte, the ID and the ETX from the message
        """
        status = False
        if len(packet) >= MIN_LENGTH:
            # All messages longer than the minimum length have a command byte
            self.cmd = packet[CMD_LOCATION:CMD_LOCATION+1]
            if len(packet) > (MIN_LENGTH + ID_LENGTH):
                # If the message is longer than min + id, the next bit is the id
                self.pkt_id = packet[ID_START:ID_START+ID_LENGTH]
#            if self.cmd in (CMD_LAST_RECORD_PTR,CMD_MISSING_DATALOG_REQ,CMD_SET_RTC,CMD_VALVE_ON):
#                # this command has the XOR at the end
#                self.pkt_etx = packet[-(LENGTH_ETX+1):-LENGTH_ETX]        #Note the minus sign
#            else:
#                self.pkt_etx = packet[-LENGTH_ETX:]        #Note the minus sign
            # the commands have the XOR at the end
            self.pkt_etx = packet[-(LENGTH_ETX+1):-LENGTH_ETX]        #Note the minus sign
            status = True
        else:
            status = False
            logging.debug("[EWD]: Packet received is below the minimum length(%s)" % len(packet))

        logging.debug("[EWD]: Incoming message command:%s" % self.cmd)
        logging.debug("[EWD]: Incoming message ID:%s" % self.pkt_id)
        logging.debug("[EWD]: Incoming message ETX Character:%s" % self.pkt_etx)
        return status
    
    def _validated(self):
        # Routine to check the incoming packet is valid and for this instance of the EWC
        if self.cmd != CMD_REQUEST_ID:
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
            for chunk,data in sorted(self.file_received.items()):
                datafile.write('{0}:{1}\r\n'.format(chunk,data))
            datafile.close()
            logging.info("[EWD] - Data File Written EWD%s" % filetime)
            self.file_written = True
        except:
            # File writing failed
           logging.warning("[EWD] - Failed to write data to the log file!: %s")

        return
    
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
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR

        logging.info("[EWD] Message To Send: Ready to Recieve Response: %s" % packet_to_send)
        return packet_to_send
    
    def _communications_failure_response(self):
        """
        Generate a communications failure response to the Chunk command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_COMMS_ERROR
        packet_to_send = packet_to_send + CMD_DATA_CHUNK
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: Communications Failure Response: %s" % packet_to_send)
        return packet_to_send

    def _firmware_received_ok(self):
        """
        Generate a communications failure response to the Chunk command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_FIRMEWARE_OK
        packet_to_send = packet_to_send + CMD_DATA_CHUNK
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: Firmware Received OK Response: %s" % packet_to_send)
        return packet_to_send

    def _chunk_received_ok(self):
        """
        Generate a communications failure response to the Chunk command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_DATA_CHUNK
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: Firmware Received OK Response: %s" % packet_to_send)
        return packet_to_send
        
    def _firmware_file_corrupt(self):
        """
        Generate a firmware file corruption response to the Chunk command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_XOR_FAILURE
        packet_to_send = packet_to_send + CMD_DATA_CHUNK
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: XOR Checksum Failure Response: %s" % packet_to_send)
        return packet_to_send

    def _spilt_chunk_message_old(self):
        """
        Taken the given packet, pull out all the constituent parts for the data chunk message)
        """
        status = False
        if len(self.message) > (PAYLOAD_START):
            # If the message is longer than the payload start, must contain the chunk id and the remainder of the data
            self.chunk = self.message[CHUNK_COUNTER_START:CHUNK_LEN_POSN]
            self.len_chunk = self.message[CHUNK_LEN_POSN]
            # At this point I know the length of the payload
            if self.len_chunk > 0:
                self.payload = self.message[PAYLOAD_START:PAYLOAD_START+self.len_chunk]
            else:
                # No Payload received, could be the last chunk..
                self.payload = b''
            status = True
        else:
            status = False
            logging.debug("[EWD]: Packet received is below the minimum length to include a payload: length received(%s)" % len(self.message))
        logging.debug("[EWD]: Incoming message Chunk Number:%s" % self.chunk)
        logging.debug("[EWD]: Incoming message Chunk Length:%s" % self.len_chunk)
        logging.debug("[EWD]: Incoming message Payload:%s" % self.payload)
        
        return status
    
    def _process_data_chunk(self):
        """
        Taking the given payload (from the _split_message function), cehck it and add it to the 
        self.file_received. If it is the end of the file, generate a file from it.
        There is no need to validate the message as the incoming stage
        Message Structure
        <CMD><ID0><ID1><ID2><ID3><Chunk MSB><Chunk LSB><Chunk LEN><byte1><byte2>..<byteN><ETX>
              self.pkt_id        self.chunk            self.len_chunk    self.payload    self.pkt_etx
        """
        response = b''
        if self.receiving_data == False:
            logging.debug("[EWD]: Starting to receive a new file")
            # Empty the dictionary
            self.file_received = {}
            self.receiving_data = True
        
        # Need to strip out the parts of the message now, 
        if len(self.message) > CHUNK_COUNTER_START:
            self.chunk = self.message[CHUNK_COUNTER_START:CHUNK_LEN_POSN]
        
        #if self._spilt_chunk_message():
        #    # Add the data received to the dictionary
        #    self.file_received[self.chunk] = self.payload
        #else:
        #    logging.warning("[EWD]: Message corrupt, communications failure as message too short")
        #    response = self._communications_failure_response()
        
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
        else:
            # Not the last chunk
            self.len_chunk = self.message[CHUNK_LEN_POSN]
            # At this point I know the length of the payload
            self.payload = self.message[PAYLOAD_START:PAYLOAD_START+self.len_chunk]

            response = self._chunk_received_ok()

        logging.debug("[EWD]: Incoming message Chunk Number:%s" % self.chunk)
        logging.debug("[EWD]: Incoming message Chunk Length:%s" % self.len_chunk)
        logging.debug("[EWD]: Incoming message Payload:%s" % self.payload)
        return response

    def _last_record_pointer(self):
        """
        Generate a last record pointer return value
        """
        packet_to_send = b''
        block = random.randint(0,255)
        pointer = random.randint(0,1023)
        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_LAST_RECORD_PTR
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + block.to_bytes(1, byteorder="big", signed=False)
        packet_to_send = packet_to_send + pointer.to_bytes(2, byteorder="big", signed=False)
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: Last Record Pointer Response: %s" % packet_to_send)
        return packet_to_send
    
    def _generate_packet(self):
        """
        Generates and returns a single packet in binary format
        EE SS MM HH DD MT YY UU UU UU UU UC UC UC UC SCR SCR SCR SCR ECR ECR ECR ECR FC FC FT FT CONVH CONVL
        0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15  16  17  18  19  20  21  22  23 24 25 26 27    28 
        """
        
        # Create an empty packet
        data_packet = b''

        # Error Code
        data_packet = data_packet + RSP_POSITIVE
        
        # Date and Time
        timenow = datetime.datetime.now()
        logging.debug("[EWD]:Date & Time being used:%s" % timenow)

        #BUG: This is not working correctly as it is not returning BCD.
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.second))
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.minute))
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.hour))
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.day))
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.month))
        data_packet = data_packet + binascii.a2b_hex('{:02d}'.format(timenow.year)[2:4])

        # 4 byte card UUID
        data_packet = data_packet + UUID

        # 4 byte usage counter
        data_packet = data_packet + USAGE

        # 4 byte start credit
        data_packet = data_packet + START_CREDIT

        # 4 byte end credit
        data_packet = data_packet + END_CREDIT

        # 2 byte flow meter count
        data_packet = data_packet + FLOW_COUNT

        # 2 byte flow meter time
        data_packet = data_packet + FLOW_TIME
        
        data_packet = data_packet + LITRE_CREDIT_CONV
        logging.debug("[EWD]:Datalog Packet Generated:%s" % data_packet)
        return data_packet
    
    def _missing_datalog_record(self):
        """
        Generate a missing datalog packet request
        """
        # Firstly extract block and pointer
        req_block = self.message[BLOCK_POSN:BLOCK_POSN+1]
        req_pointer = self.message[POINTER_START:POINTER_START+2]

        packet_to_send = b''

        packet_to_send = packet_to_send + CMD_DATALOG_PACKET
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + self._generate_packet()
        packet_to_send = packet_to_send + req_block
        packet_to_send = packet_to_send + req_pointer
        packet_to_send = packet_to_send + ETX_CHAR
        xor = self._add_xor(packet_to_send)

        logging.info("[EWD] Message To Send: Datalog Packet Response: %s" % packet_to_send)
        return packet_to_send

    def _set_rtc_response(self):
        """
        Generate a positive response to the Set RTC
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_SET_RTC
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR

        xor = self._add_xor(packet_to_send)
        packet_to_send = packet_to_send + xor

        logging.info("[EWD] Message TO Send: Set RTC Response: %s" % packet_to_send)
        return packet_to_send
        
    def _valve_on_response(self):
        """
        Generate a positive response to the Valve On command
        """
        packet_to_send = b''

        packet_to_send = packet_to_send + RSP_POSITIVE
        packet_to_send = packet_to_send + CMD_VALVE_ON
        packet_to_send = packet_to_send + self.ewc
        packet_to_send = packet_to_send + ETX_CHAR

        xor = self._add_xor(packet_to_send)
        packet_to_send = packet_to_send + xor

        logging.info("[EWD] Message TO Send: Valve On Response: %s" % packet_to_send)
        return packet_to_send
        
def main():
	
	return 0

if __name__ == '__main__':
	main()

