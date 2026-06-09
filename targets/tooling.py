# interacts with the FPGA's UART interface to provide glitching parameters

import serial
import os 
import logging
import struct
import time
import pickle
import threading
import secrets

from pyocd.core.helpers import ConnectHelper

TRIALS = 10  # number of trials to do per glitch parameter

class FPGAParameters():
    def __init__(self, port: str, baud: int=115200, fpga_speed: int=200, target_speed: int=32, delay: int=0, length: int=5):
        """
        Initializes an FPGAParameters object
        :param port: the serial port for the FPGA
        :param baud: the baud rate of the UART connection
        :param fpga_speed: the speed of the FPGA in MHz
        :param target_speed: the speed of the target in MHz
        :param delay: how long to delay after a trigger before the glitch, in the target's clock cycles
        :param length: how long to do the glitch for, in FPGA clock cycles, in the FPGA's clock cycles
        """
        self.logger = logging.getLogger("FPGAParameters")
        if delay < 0 or length < 0:
            raise ValueError("The delay and/or length must be nonnegative")
        self.fpga_speed = fpga_speed
        self.target_speed = target_speed
        self.delay = delay
        self.length = length
        self.ser = serial.Serial(port, baud, timeout=1)
        self.delay_delta = 0
        self.length_delta = 0
        self.bg_thread = None
        self.bg_thread_running = False

    def serialize_delay(self) -> bytes:
        out = b''
        for b in struct.pack(">I", self.get_delay()):
            out += b.to_bytes(1)
        return b'\xFF' + out

    def serialize_length(self) -> bytes:
        return b'\x00' + struct.pack(">B", self.get_length())

    def serialize(self) -> bytes:
        """
        Serializes the FPGAParameters to be sent over UART
        """
        # reset it then send the delay and the length
        return b'\xaa' + self.serialize_delay() + self.serialize_length()

    def send(self):
        """
        Sends the serialized parameters to the FPGA and waits for an ACK
        """

        for b in self.serialize():
            self.logger.debug(f"Sending {b.to_bytes(1)} to the FPGA")
            self.ser.reset_input_buffer()
            self.ser.write(b.to_bytes(1))
            self.ser.flush()
            res = self.ser.read()
            self.logger.debug(f"Got {res} from the FPGA")
            if not res:
                raise Exception("FPGA timed out")
    
    def set_delay_delta(self, delta: int=0):
        """
        Sets the delta for the delay
        :param delta: the new delta in terms of the FPGA's clock cycles
        """
        if round(self.delay * (self.fpga_speed / self.target_speed) + delta) < 0:
            raise ValueError("Delta cannot be less than the current delay")
        self.delay_delta = delta

    def set_length_delta(self, delta: int=0):
        """
        Sets the delta for the length of the glitch
        :param delta: the new delta in terms of the FPGA's clock cycles
        """
        if self.length + delta < 0:
            raise ValueError("Delta cannot be less than the current glitch length")
        self.length_delta = delta

    def get_delay(self) -> int:
        """
        Get the current delay, including the delta
        :return: delay [target] + delta [FPGA] 
        """
        return round(self.delay * (self.fpga_speed / self.target_speed) + self.delay_delta)

    def get_length(self) -> int:
        """
        Get the current length, including the delta
        :return: length [FPGA] + delta [FPGA]
        """
        return self.length + self.length_delta

    def close(self):
        """
        Close the serial connection
        """
        self.logger.info("Closing the FGPA serial connection")
        self.stop_background_listener()
        self.ser.close()

    def start_background_listener(self):
        self.ser.reset_output_buffer()
        self.ser.reset_input_buffer()
        self.bg_thread = threading.Thread(target=self._bg_thread)
        self.bg_thread_running = True
        self.bg_thread.start()

    def stop_background_listener(self):
        self.bg_thread_running = False
        if self.bg_thread is not None and self.bg_thread.is_alive():
            self.bg_thread.join()
        self.bg_thread = None

    def _bg_thread(self):
        self.logger.debug("Starting the FPGA background thread")
        while self.bg_thread_running:
            msg = self.ser.read_all()
            if len(msg) != 0:
                self.logger.info(f"FPGA background thread got {msg}")

class TargetDevice():
    def __init__(self, expected_output: bytes, port: str, baud: int=115200, timeout: int=1):
        """
        :param expected_output: the expected output from the program on a successful glitch
        :param port: the serial port of the target device
        :param baud: the baud rate of the UART connection to the board
        :param timeout: the timeout for the serial connection to the board
        """
        self.logger = logging.getLogger("TargetDevice")
        self.expected_output = expected_output
        self.ser = serial.Serial(port, baud, timeout=timeout)

    def set_setup_callback(self, setup):
        """
        Sets the function to be ran for setting up a glitch
        :param setup: the setup function to be ran
        """
        self.setup = setup

    def run(self, program_input: bytes):
        """
        Runs the program a single time.  Calls the setup callback then waits for input.
        :param program_input: the input to give the program on this run
        :return: whether or not the glitch was successful
        """
        self.logger.info("Running the program")
        self.setup(self.ser, program_input)
        self.logger.info("All set up")
        time.sleep(.1)  # waiting for the results of the glitch
        real_output = self.ser.read_all()  # read the results
        self.logger.info(f"Got the following output {real_output}")
        if real_output:
            self.logger.critical(f"Got the following output {real_output}")
        return (self.expected_output in real_output)# or (b'pwned!' in real_output)
    
    def close(self):
        """
        Close the serial connection
        """
        self.logger.critical("Closing serial connection")
        self.ser.close()

SESSION = ConnectHelper.session_with_chosen_probe(target_override="mspm0l2228")  # NOTE: change board here
SESSION.open()
OCD_TARGET = SESSION.board.target

logging.getLogger("TargetDevice").setLevel(logging.CRITICAL)
logging.getLogger("FPGAParameters").setLevel(logging.CRITICAL)

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.CRITICAL
)
def setup_device(ser: serial.Serial, program_input: bytes):
    # NOTE: this is part of the tool that is very dependent on the target
    # This example for for targets that just reads at the beginning
    # reset the device
    # subprocess.run(["dslite", "-c", "MSPM0L2228.ccxml", "-r", "1"], stdout=subprocess.DEVNULL)  # backup if pyocd doens't work
    OCD_TARGET.dp.reset()  # send reset via OCD
    time.sleep(.05)  # wait for reset to complete
    # clear buffers for a fresh start
    ser.reset_output_buffer()
    ser.reset_input_buffer()
    parameters.send()  # also resets the board
    parameters.start_background_listener()
    ser.write(program_input)


target = TargetDevice(expected_output=b'', port='/dev/ttyACM0', baud=115200, timeout=1)
parameters = FPGAParameters(port='/dev/ttyUSB0', baud=115200)
target.set_setup_callback(setup_device)

parameters.length = 5  # NOTE: this depends on your target's clock speed

for folder_name in ['', '2', '3', '4', None]:
    # get the expected output from file
    if folder_name is None:
        target.expected_output = b'pwned'  # catch any
        # since None is last, we can just reuse options from the last loop
    else:
        with open(f'./timspm0l2228/aes_ecb/pwned{folder_name}/expected.bin', 'rb') as f:  # NOTE: change the expected output here
            target.expected_output = f.read()
        # get the glitch parameters
        with open(f'./timspm0l2228/aes_ecb/pwned{folder_name}/exported.pkl', 'rb') as f:  # TODO: change the exported faults found here
            options = pickle.load(f)
        # only supports index = 0 (i.e, first after the trigger), so clear those where index != 0
        options = [option for option in options if option.get("index") == 0]

    successes = []
    success_rate = []
    try:
        for current_glitch in options:
            tries = 0
            successful_glitches = 0
            # give an extra 5 target cycles
            for delay in range(max(current_glitch['cycles_after_trigger'][0] - 6, 1), current_glitch['cycles_after_trigger'][2] + 5):
                parameters.delay = delay
                for delay_delta in range(-6, 1):  # -6 to 0, going by 1
                    parameters.set_delay_delta(delay_delta)
                    for length in range(0, 1):  # -2 to 2, going by 1
                        parameters.set_length_delta(length)
                        logging.info(f"Trying {TRIALS} attempts with {parameters.get_delay()} delay and {parameters.get_length()} length")
                        for _ in range(TRIALS):
                            tries += 1
                            if target.run(current_glitch['input']):
                            # if target.run(b'\xFF' * len(current_glitch['input'])):
                                logging.critical(f"Successful fault with {parameters.get_delay()} delay cycles with {parameters.get_length()} glitching length cycles")
                                successes.append({ "delay": parameters.get_delay(), "length": parameters.get_length() })
                                successful_glitches += 1
                            parameters.stop_background_listener()
            success_rate.append(successful_glitches / tries)
    except KeyboardInterrupt:
        logging.critical("Ending tool.")
    finally:
        # Close the serial when done
        parameters.close()
        target.close()
        SESSION.close()

    logging.critical("Finished run, results:")
    with open(f"out{folder_name}.txt", "w") as f:
        for success in successes:
            logging.critical(f"Delay: {success['delay']}\nLength: {success['length']}")
            f.write(f"Delay: {success['delay']}\nLength: {success['length']}\n")
        print(success_rate)
        f.write(str(success_rate))

"""
#l = len(options[1]['input'])
#TRIALS = 500
#tries = 0
#successful_glitches = 0
#try:
#    for delay in range(735, 736):
#        parameters.delay = delay
#        parameters.set_length_delta(0)
#        for i in range(-8, 1, 1):
#            parameters.set_delay_delta(i)
#            logging.info(f"Trying {TRIALS} attempts with {parameters.get_delay()} delay")
#            for _ in range(TRIALS):
#                tries += 1
#                if target.run(secrets.token_bytes(len(options[1]['input']))):
#                # if target.run(options[1]['input']):
#                    logging.critical(f"Successful fault with {parameters.get_delay()} delay")
#                    successful_glitches += 1
#                parameters.stop_background_listener()
#except KeyboardInterrupt:
#    logging.critical("Quitting")
#finally:
#    parameters.close()
#    target.close()
#    SESSION.close()
#logging.critical(f"Success rate: {successful_glitches / tries}")
#quit()
"""