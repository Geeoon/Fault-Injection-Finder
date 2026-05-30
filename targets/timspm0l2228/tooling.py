# interacts with the FPGA's UART interface to provide glitching parameters

import serial
import os 
import logging
import struct
import time
import pickle

from pyocd.core.helpers import ConnectHelper

TRIALS = 5  # number of trials to do per glitch parameter

class FPGAParameters():
    def __init__(self, port: str, speed: int=115200, delay: int=0, length: int=5):
        """
        Initializes an FPGAParameters object
        :param delay: how long to delay after a trigger before the glitch, in FPGA clock cycles
        :param length: how long to do the glitch for, in FPGA clock cycles
        """
        self.logger = logging.getLogger("FPGAParameters")
        if delay < 0 or length < 0:
            raise ValueError("The delay and/or length must be nonnegative")
        self.delay = delay
        self.length = length
        self.ser = serial.Serial(port, speed, timeout=1)
        self.delay_delta = 0
        self.length_delta = 0

    def serialize(self) -> bytes:
        """
        Serializes the FPGAParameters to be sent over UART
        """
        # send the delay, then the length, then reset it
        return ((0b10101010).to_bytes(1), b'\0' + struct.pack(">I", self.get_delay()),  b'\xFF' + struct.pack(">B", self.get_length()))

    def send(self):
        """
        Sends the serialized parameters to the FPGA and waits for an ACK
        """
        for packet in self.serialize():
            self.logger.info(f"Sending {packet} to the FPGA")
            self.ser.write(packet)
            res = self.ser.read()
            self.logger.info(f"Got {res} from the FPGA")
            if not res:
                raise Exception("FPGA timed out")
    
    def set_delay_delta(self, delta: int=0):
        """
        Sets the delta for the delay
        :param delta: the new delta
        """
        if self.delay + delta < 0:
            raise ValueError("Delta cannot be less than the current delay")
        self.delay_delta = delta

    def set_length_delta(self, delta: int=0):
        """
        Sets the delta for the length of the glitch
        :param delta:
        """
        if self.length + delta < 0:
            raise ValueError("Delta cannot be less than the current glitch length")
        self.length_delta = delta

    def get_delay(self) -> int:
        """
        Get the current delay, including the delta
        :return: delay + delta
        """
        return self.delay + self.delay_delta

    def get_length(self) -> int:
        """
        Get the current length, including the delta
        :return: length + delta
        """
        return self.length + self.length_delta

    def close(self):
        """
        Close the serial connection
        """
        self.logger.info("Closing the FGPA serial connection")
        self.ser.close()


class TargetDevice():
    def __init__(self, expected_output: bytes, port: str, speed: int=115200, timeout: int=1):
        """
        :param port: port the serial port of the target device
        """
        self.logger = logging.getLogger("TargetDevice")
        self.expected_output = expected_output
        self.ser = serial.Serial(port, speed, timeout=timeout)

    def set_setup_callback(self, setup):
        """
        Sets the function to be ran for setting up a glitch
        :param setup: the setup function to be ran
        """
        self.setup = setup

    def run(self):
        """
        Runs the program a single time.  Calls the setup callback then waits for input.
        :return: whether or not the glitch was successful
        """
        self.logger.info("Running the program")
        self.setup(self.ser)
        time.sleep(.05)
        real_output = self.ser.read_all()
        self.logger.info(f"Got the following output {real_output}")
        return self.expected_output in real_output
    
    def close(self):
        """
        Close the serial connection
        """
        self.logger.info("Closing serial connection")
        self.ser.close()


SESSION = ConnectHelper.session_with_chosen_probe(target_override="mspm0l2228")
SESSION.open()
OCD_TARGET = SESSION.board.target
def setup_device(ser: serial.Serial):
    # NOTE: this is part of the tool that is very dependent on the target
    # This example for for targets that just reads at the beginning
    # reset the device
    # subprocess.run(["dslite", "-c", "MSPM0L2228.ccxml", "-r", "1"], stdout=subprocess.DEVNULL)
    OCD_TARGET.dp.reset()
    # clear buffers for a fresh start
    ser.reset_output_buffer()
    ser.reset_input_buffer()
    # read input from file
    program_input = b''
    with open('./input.bin', "rb") as f:  # TODO: change path to actual path
        program_input = f.read()
    ser.write(program_input)


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING
)

logging.getLogger("TargetDevice").setLevel(logging.DEBUG)
logging.getLogger("FPGAParameters").setLevel(logging.DEBUG)

# get the expected output from file
with open('./expected.bin', 'rb') as f:  # TODO: make this a command line argument
    expected = f.read()
# get the glitch parameters
with open('./exported.pkl', 'rb') as f:  # TODO: make this a command line argument
    options = pickle.load(f)
print(options)

target = TargetDevice(expected_output=expected, port='/dev/ttyACM0', speed=115200, timeout=1)
target.set_setup_callback(setup_device)
# parameters = FPGAParameters(port='/dev/ttyACM1', speed=115200)  # TODO: change to be the actual FPGA port

successes = []
try:
    # send the parameters to the FPGA
    for delay_delta in range(-10, 11):  # -10 to 10, going by 1
        for length in range(-2, 3, 2):  # -2 to 2, going by 1
            # parameters.set_delay_delta(delay_delta)
            # parameters.set_length_delta(length)
            # logging.info(f"Trying {TRIALS} attempts with {parameters.get_delay()} delay and {parameters.get_length()} length")
            for _ in range(TRIALS):
                # parameters.send()
                if target.run():
                    pass
                    # logging.critical(f"Successful fault with {parameters.get_delay()} delay cycles with {parameters.get_length()} glitching length cycles")
                    # successes.append({ "delay": parameters.get_delay(), "length": parameters.get_length() })
except KeyboardInterrupt:
    logging.info("Ending tool.")
finally:
    # Close the serial when done
    # parameters.close()
    target.close()
    SESSION.close()

logging.info("Finished run, results:")
for success in successes:
    logging.critical(f"Delay: {success['delay']}\nLength: {success['length']}")
