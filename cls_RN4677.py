"""

  cls_RN4677.py
  
  Copyright 2017  <Bostin Technology>

This class provides all the functionality to talk to the RN4677 Bluetooth module

Public functions are
- Transmit
- Receive
- Exit

    Setup is completed on initialisation

BUG: When reading from the serial port, it doesn't check for data, but using the timeout instead

BUG: Use the below code instead of what I currently have as the current method relies on the lower level
    module to do all the work.
>>> while True:
	if ser.in_waiting:
		print("%s" % ser.readall())
    Consider having it read a character at a time and use the timeouts differently.

BUG: Sometimes when rebooting, it misses the reboot responses.

TODO: Need to go through and add timeouts
"""

import logging
import serial
import sys
import datetime
import time


BAUDRATE = 115200           # The speed of the comms
PORT1 = "/dev/serial0"      # The primary port being used for the comms
PORT2 = "dev/ttyAMA0"       # The secondary port to try if the first fails
BLT_TIMEOUT = 1#.5           # The maximum time allowed to wait for a message on the serial port
INTERDELAY = 0.01            # The delay between receiving one message via the Bluetooth module and sending the next message
                            # Typically used when configuring the Bluetooth module
COMMS_TIMEOUT = 20          # During processing of Bluetooth messages, there is a timeout to determine if the message is old
                            # This is measured in seconds
SRDELAY = 0.001              # The delay between send and receive of data using the UART to the Bluetooth module
                            # This is not a delay between messages, but the UART level comms
RETRY_COUNT = 3             # The retry count is how many times it is going to send the command to retry it.
REBOOT_TIME = 10            # The maximum time allowed for the bluetooth module to reboot




WAKEUP = b'$$$'             # The Bluetooth wakeup command to enter command mode
READ_ALL_SETTINGS = b'X'    # Read all the settings from the module
VERSION = b'V'              # Read the version information from the module
REBOOT = b'R,1'             # Reboot the bluetooth module
END_COMMS = b'---'          # End the command session
CONNECTION_STATUS = b'GK'   # Requests the connection status from the module

POSITIVE_RSP = b'AOK'
NEGATIVE_RSP = b'Err'
UNKNOWN_COMMAND = b'?'
COMMAND_RSP = b'CMD>'
END_RSP = b'END'
REBOOT_STARTED_RSP = b'Rebooting'   # Sent the when the module has started rebooting
REBOOT_RSP = b'%REBOOT%'            # Sent when the module has rebooted
NEW_PAIRING = b'%NEW_PAIRING%'      # Sent when a new device is pairing
CONNECT = b'%CONNECT'               # Sent as the first part of the message when a devioce connects
DISCONNECT = b'%DISCONNECT%'        # MEssage sent when the device disconnects
CR_LF = b'\r\n'             # The bits to add after a command to send it, initially set to b'\r\n'

POSITIVE_RSP_POSN = 10      # The number of characters from the end where the positive response starts
COMMAND_RSP_POSN = 5        # The number of characters from the end where the command start

# Bluetooth setup
#   The following commands are sent to setup the bluetooth module.
SETUP_BLUETOOTH = [b'SF,1',b'SM,0', b'SG,0', b'SN,eWaterPay Tap', b'SS,SPP eWaterPay', b'SA,2', b'SP,123456']  #b'SP,2551']
"""                  SF,1 - Factory Reset
                             SM,0 - Slave Mode
                                      SG,0 - Dual Mode
                                               SN - Device Name
                                                                    SS - Service Name
                                                                                        SA,2 - SSP "Just Works" mode
                                                                                        SA,4 - Legacy Pin mode
                                                                                                SP - Pin number
"""
class RN4677:
    """
    This class handles the communications to the RN4677 bluetooth module
    
    Private functions are preceded with an underscore '_'
    
    """
    
    def __init__(self):
        """
        Performs the Pi setup and configuration
        """
        print("Initialising Bluetooth Module")
        self.incommsmode = False                # Set to true when successfully got into cmd mode
        self.fd = self._setup_uart()
        if self._setup_bluetooth() == False:
            logging.critical("[BLT]: Unable to initiate comms with the Bluetooth module")
            print("Unable to initiate comms with the Bluetooth module")
            sys.exit()
        self.comms_status = True

    def connection_status(self):
        """
        Returns the status of any connected devices
        True if the devices is connected as SPP, not in BLE mode
        """
        response = ""
        #Note: Need to check if in command mode first.
        if self._bluetooth_command_mode_wakeup():
            reply = self._send_command(CONNECTION_STATUS, aok=False)
            # reply will contain the response -> 3 digits seperated by comma
            connection_status = reply[1].split(b',')
            if len(connection_status) < 3:
                logging.error("[BLT]: Connection Status returned incorrect status, got:%s" % reply)
                return response
            logging.debug("[BLT]: Number of connected devices:%s" % connection_status[0])
            logging.debug("[BLT]: Authentication Status (0= No BLE authentication) :%s" % connection_status[1])
            logging.debug("[BLT]: Connection Type (0 = SPP):%s" % connection_status[2])
            if (connection_status[0] == b'1' and connection_status[2] == b'0'):
                response = True
            else:
                response = False
        self._end_comms()
        return response
    
    def waiting_for_connection(self, timeout=30):
        """
        Waits until the device receives a connection, either existing or new
        timeout is the number of seconds to wait
        Returns status[0] = True if connected, and status[1] = True if a new device
        """
        logging.info("[BLT]: Waiting for a connection")
        status = []
        status = [False, False]
        endtime = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
        connected = False
        while endtime > datetime.datetime.now() or connected == True:
            response = self._read_from_sp()
            if NEW_PAIRING in response:
                status[1] = True
            elif CONNECT in response:
                status[0] = True
                connected = True
        logging.debug("[BLT]: Connection status:%s (1=Connected, 1=New pairing)" % status)
        self._end_comms()
        return status
    
    def receive_data(self, lengthdata=-1):
        """
        Capture whatever data over the serial port and return it
        lengthdata defines how many bytes to receive
        """
        logging.info("[BLT]: Receiving data of length %s" % lengthdata)
        response = self._read_from_sp(lengthdata)
        response = response.strip(b'\r\n')
        return response
    
    def send_data(self, packet):
        """
        Send the given packet to the bluetooth device, mo response
        """
        send_status = False
        self._write_to_sp(packet)
        return

    def exit_comms(self):
        """
        This routine is to be called on the exit of the main program
        """
        logging.info("[BLT]: Exiting Comms")
        self._end_comms()
        self.fd.close()
        return
        
    def comms_status(self):
        """
        Returns the current status of the comms
        
        """
        
        return self.comms_status

#-----------------------------------------------------------------------
#
#    P R I V A T E   F U N C T I O N S
#
#-----------------------------------------------------------------------

    def _setup_uart(self):
        """
        Setup the UART for communications and return an object referencing it. Does:-
        -Initiates serial software
        -Opens the serial port
        -Checks all is ok and returns the object
        """
        try:
            ser = serial.Serial(PORT1,
                                baudrate=BAUDRATE,
                                parity=serial.PARITY_NONE,
                                stopbits=serial.STOPBITS_ONE,
                                bytesize=serial.EIGHTBITS,
                                timeout=BLT_TIMEOUT)
        except:
            logging.critical("[BLT]: Unable to Setup communications on Serial0, trying ttyAMA0")
            ser = ''

        if ser =='':
            try:
                ser = serial.Serial(PORT2,
                                    baudrate=BAUDRATE,
                                    parity=serial.PARITY_NONE,
                                    stopbits=serial.STOPBITS_ONE,
                                    bytesize=serial.EIGHTBITS,
                                    timeout=BLT_TIMEOUT)
            except:
                logging.critical("[BLT]: Unable to Setup communications on ttyAMA0")
                sys.exit()

        time.sleep(INTERDELAY)

        # clear the serial buffer of any left over data
        ser.flushInput()

        if ser.isOpen():
            # if serial comms are setup and the channel is opened
            logging.info ("[BLT]: PI UART setup complete on channel %d as : %s" % (ser.fd, ser.getSettingsDict))
        else:
            logging.critical("[BLT]: Unable to Setup communications")
            sys.exit()
        return ser
        
    def _write_to_sp(self, data_to_transmit):
        """ 
        Write the given data to the serial port
        Returns the data length or 0 if failed
        add the control characters
        """
        send = data_to_transmit

        try:
            ans = self.fd.write(send)
            logging.info("[BLT]: Message >%s< written to Bluetooth module and got response :%s" % (data_to_transmit, ans))
        except Exception as e:
            logging.warning("[BLT]: Message >%s< sent as >%a< FAILED" % (data_to_transmit, send))
            ans = 0
        return ans

    def _read_from_sp(self, length=-1):
        """
        Read data from the serial port, using length if given
        return the data, length of zero if nothing of failed
        """
        logging.debug("[BLT]: Start of read - timestamp")
        reply = b''
        try:
            if length == -1:
                #length = self.fd.inWaiting()
                ##TODO: Possibly use the inWaiting capability rather than readall
                ##BUG: This can now return immediately and therefore mess up the rest of the comms - reverted to old code
                #if length > 0:
                #    reply = self.fd.read(length)
                #BUG: If the length is longer than what is read, it returns without reading any more
                
                reply = self.fd.readall()
                #reply = self.fd.readline() - doesn't work as the \r\n come before the CMD
                
            else:
                reply = self.fd.read(length)
        except:
            logging.warning("[BLT]: Reading of data on the serial port FAILED")
            reply = b''

        logging.debug("[BLT]: Data read back from the serial port :%s" % reply)
        return reply

    def _check_blt_response(self, receive, aok=True, cmd=True):
        """
        For the given response, check the bluetooth reply is a positive reply
        return True if it is, else False if it isnt, capturing the error message
        if aok or cmd set to False, won't check for them
        A good response may have AOK before the 'CMD>' prompt
        """
        if aok:
            if len(receive) < POSITIVE_RSP_POSN:
                logging.warning("[BLT]: Response received is too short for AOK message:%s" % receive)
                return False

            if POSITIVE_RSP not in receive[len(receive) - POSITIVE_RSP_POSN:]:
                response = receive[len(receive) - POSITIVE_RSP_POSN:]
                logging.warning("[BLT]: Negative response received from the Bluetooth module:%s" % response)
                return False

        if cmd:
            if len(receive) < COMMAND_RSP_POSN:
                logging.warning("[BLT]: Response received is too short for CMD message:%s" % receive)
                return False

            if COMMAND_RSP not in receive[len(receive) - COMMAND_RSP_POSN:]:
                response = receive[len(receive) - COMMAND_RSP_POSN:]
                logging.warning("[BLT]: No command prompt received from the Bluetooth module:%s" % response)
                return False
        
        logging.info("Message checked for Positive and Command responses")
        return True

    def _bluetooth_command_mode_wakeup(self):
        """
        This function sends the wakeup command and waits for the response
        """
        logging.info("[BLT]: Waking up the Bluetooth module in command mode")
        working = False
        # Check if in CMD mode already
        try:
            ans = self.fd.write(b'?\r\n')
            logging.info("[BLT]: Wake-up check message >?+CR+LF< written to Bluetooth module and got response :%s" % ans)
        except Exception as e:
            logging.warning("[BLT]: Wake-up check message >?+CR+LF< sent FAILED")
        if ans > 0:
            time.sleep(SRDELAY)
            # No need to check the reply as it has already been validated
            reply = self._read_from_sp()

            working = self._check_blt_response(reply, aok=False)
        
        logging.debug("[BLT]: Command Mode Status:%s" % working)

        endtime = datetime.datetime.now() + datetime.timedelta(seconds=COMMS_TIMEOUT)
        while (endtime > datetime.datetime.now()) and working == False:
            try:
                ans = self.fd.write(WAKEUP)
                logging.info("[BLT]: Wake-up message >%s< written to Bluetooth module and got response :%s" % (WAKEUP, ans))
            except Exception as e:
                logging.warning("[BLT]: Wake-up message >%s< sent FAILED" % (WAKEUP))
                ans = 0

            if ans > 0:
                time.sleep(SRDELAY)
                # No need to check the reply as it has already been validated
                reply = self._read_from_sp()

                working = self._check_blt_response(reply, aok=False)

#                if working == False:
#                    logging.debug("[BLT]: Wake-up message response is false, trying resetting of comms")
#                    #Try clearing and send a carriage return to clear
#                    self.fd.flushInput()
#                    self.fd.write(b'?\r\n')
#                    reply = self._read_from_sp()
#                    working = self._check_blt_response(reply, aok=False)
                 
            else:
                logging.warning("[BLT]: Failed to get a response from the Config Command %s" % WAKEUP)

        


        self.incommsmode = working
        return working

    def _send_command(self, command, aok=True, cmd=True):
        """
        This function sends data and gets the reply for the various commands, including configuration ones.
        Tries for the RETRY_COUNT times before returning.
        Returns the data received from the 
        """
        tries = RETRY_COUNT
        command = command + CR_LF
        reply = b''
        while tries > 0: 
            ans = self._write_to_sp(command)
            if ans > 0:
                time.sleep(SRDELAY)
                reply = self._read_from_sp()
                if self._check_blt_response(reply, aok):
                    logging.debug("[BLT]: Sent Command successfully: %s" % command)
                    break
            else:
                logging.warning("[BLT]: Failed to Send Command %s" % command)
            tries = tries - 1
        return [(tries > 0), reply]

    def _send_config_command_old(self, command, aok=True, cmd=True):
        """
        This function sends data and gets the reply for the various configuration commands.
        Tries for the RETRY_COUNT times before returning.
        """
        tries = RETRY_COUNT
        command = command + CR_LF
        reply = b''
        while tries > 0: 
            ans = self._write_to_sp(command)
            if ans > 0:
                time.sleep(SRDELAY)
                reply = self._read_from_sp()
                if self._check_blt_response(reply, aok):
                    logging.debug("[BLT]: Sent Command successfully: %s" % command)
                    break
            else:
                logging.warning("[BLT]: Failed to Send Command %s" % command)
            tries = tries - 1
        return reply

    def _reboot_module(self):
        """
        Used to reboot the module, checks for the 2 expected responses
        - rebooting
        - %REBOOT%
        reboot can be set to 
        - 0 for Not Started
        - 1 sent command
        - 2 - 9 for the steps of progress (received first response, received last response)
        - 10 completed
        - 99 failed
        """
        logging.info("[BLT]: Rebooting the Bluetooth module")
        tries = RETRY_COUNT
        command = REBOOT + CR_LF
        
        reboot = 0
        while tries > 0 and reboot != 10:
            ans = self._write_to_sp(command)
            if ans > 0:
                reboot = 1
                endtime = datetime.datetime.now() + datetime.timedelta(seconds=REBOOT_TIME)
                while reboot < 10:
                    time.sleep(SRDELAY)
                    reply = self._read_from_sp()        # reply could contain one or both responses
                    logging.debug("[BLT]: Rebooting Status: %s" % reboot)
                    if REBOOT_STARTED_RSP in reply:
                        logging.debug("[BLT]: Rebooting started")
                        reboot = 2
                    if REBOOT_RSP in reply:
                        logging.debug("[BLT]: Sent REBOOT Command successfully: %s" % command)
                        reboot = 10
                    if endtime < datetime.datetime.now():
                        logging.debug("[BLT]: Rebooted timeout occurred")
                        reboot = 99
            else:
                logging.warning("[BLT]: Failed to Send REBOOT Command %s" % command)
            tries = tries - 1
            logging.debug("[BLT]: Number of retries remaining: %s" % tries)
        if reboot == 10:
            self.incommsmode = False
        return (reboot == 10)

    def _reboot_module_old(self):
        """
        Used to reboot the module, checks for the 2 expected responses
        - rebooting
        - %REBOOT%
        """
        logging.info("[BLT]: Rebooting the Bluetooth module")
        tries = RETRY_COUNT
        command = REBOOT + CR_LF
        rebooting = True
        while tries > 0 or rebooting == False:
            ans = self._write_to_sp(command)
            if ans > 0:
                rebooting = True
                while rebooting:
                    # TODO: Add a timeout to this function
                    time.sleep(SRDELAY)
                    reply = self._read_from_sp()
                    if len(reply) < min(len(REBOOT_RSP), len(REBOOT_STARTED_RSP)):
                        logging.warning("[BLT]: Length of REBOOT command response received is too short:%s" % reply)
                        break
                    elif REBOOT_STARTED_RSP in reply:
                        logging.debug("[BLT]: Rebooting started")
                    elif REBOOT_RSP in reply:
                        logging.debug("[BLT]: Sent REBOOT Command successfully: %s" % command)
                        rebooting = False
                    else:
                        logging.warning("[BLT]: Incorrect response received from the REBOOT command to the Bluetooth module:%s" % reply)
                        break
            else:
                logging.warning("[BLT]: Failed to Send REBOOT Command %s" % command)
            tries = tries - 1
        return

    def _read_config_data_from_sp(self):
        """
        Read the configuration data from the bluetooth device
        return True if completed
        """
        tries = RETRY_COUNT
        command = READ_ALL_SETTINGS + CR_LF
#        reply = b''
        while tries > 0: 
            ans = self._write_to_sp(command)
            if ans > 0:
                time.sleep(SRDELAY)
                reply = b''
                readinginprogress = True
                while readinginprogress:
                    lineread = self.fd.readline()
                    logging.debug("[BLT]: Configuration data read back from the serial port :%s" % lineread)
                    if lineread == b'':
                        readinginprogress = False
                    else:
                        reply = reply + lineread
                if self._check_blt_response(reply, aok=False):
                    logging.debug("[BLT]: Configuration data read back successfully: %s" % command)
                    break       #Only breaks out of this while statement, not the whole loops

            else:
                logging.warning("[BLT]: Failed to Send Configuration info Command %s" % command)
            tries = tries - 1
        return (tries > 0)


    def _setup_bluetooth(self):
        """
        Setup the Bluetooth module configuration
        """
        logging.info("[BLT]: Setting up the Bluetooth module with the various commands")
        bcmw = self._bluetooth_command_mode_wakeup()
        if bcmw == False:
            sys.exit()
        time.sleep(INTERDELAY)
        
        # self._read_device_settings()
        rcdfs = self._read_config_data_from_sp()
        time.sleep(INTERDELAY)

        sc = self._send_command(VERSION, aok=False)
        time.sleep(INTERDELAY)

        stsc = True
        for msg in SETUP_BLUETOOTH:
            status = self._send_command(msg, aok=True)
            stsc = stsc & status[0]
            time.sleep(INTERDELAY)
        rm = self._reboot_module()
        time.sleep(INTERDELAY)
        
        return (bcmw & rcdfs & sc[0] & stsc & rm)

    def _end_comms(self):
        """
        End the comms with the module
        """
        if self.incommsmode == False:
            # Not in comms mode, so no point sending response
            return
        tries = RETRY_COUNT
        command = END_COMMS + CR_LF
        while tries > 0: 
            ans = self._write_to_sp(command)
            if ans > 0:
                time.sleep(SRDELAY)
                reply = self._read_from_sp()
                if len(reply) < len(END_RSP):
                    logging.warning("[BLT]: Length of END command response received is too short:%s" % reply)
                elif END_RSP in reply:
                    logging.debug("[BLT]: Sent END Command successfully: %s" % command)
                    break
                else:
                    logging.warning("[BLT]: Incorrect response received from the END command to the Bluetooth module:%s" % reply)
            else:
                logging.warning("[BLT]: Failed to Send END Command %s, maybe not in CMD mode" % command)
            tries = tries - 1
        return
