#include <errno.h>

#include <ti/devices/msp/msp.h>
#include <ti/driverlib/driverlib.h>
#include <ti/driverlib/m0p/dl_core.h>


#define STATUS_LED_ON() DL_GPIO_setPins(LEDS_PORT, LEDS_STATUS_LED_PIN)
#define STATUS_LED_OFF() DL_GPIO_clearPins(LEDS_PORT, LEDS_STATUS_LED_PIN)

#define LEDS_PORT                                                        (GPIOB)
#define LEDS_STATUS_LED_PIN                                     (DL_GPIO_PIN_14)
#define LEDS_STATUS_LED_IOMUX                                    (IOMUX_PINCM35)

#define POWER_STARTUP_DELAY             (16)
#define CPUCLK_FREQ                     32000000

// change UART here
#define UART_ADDR                       (UART_Regs*)UART0_BASE 
#define BAUD_RATE                       115200

void init_device(void) {
    // UART configuration
    DL_UART_Config config = {
        .mode = DL_UART_MODE_NORMAL,
        .direction = DL_UART_DIRECTION_TX_RX,
        .flowControl = DL_UART_FLOW_CONTROL_NONE,
        .parity = DL_UART_PARITY_NONE,
        .wordLength = DL_UART_WORD_LENGTH_8_BITS,
        .stopBits = DL_UART_STOP_BITS_ONE
    };

    DL_UART_ClockConfig clk_config = {
        .clockSel = UART_CLKSEL_BUSCLK_SEL_ENABLE,
        .divideRatio = UART_CLKDIV_RATIO_DIV_BY_1
    };

    DL_UART_reset(UART_ADDR);
    DL_UART_enablePower(UART_ADDR);
    delay_cycles(POWER_STARTUP_DELAY);
    // NOTE: this is specific to UART0, if we use another, this should also be changed
    DL_GPIO_initPeripheralOutputFunction(
        IOMUX_PINCM25, IOMUX_PINCM25_PF_UART0_TX);
    DL_GPIO_initPeripheralInputFunction(
        IOMUX_PINCM26, IOMUX_PINCM26_PF_UART0_RX);

    DL_UART_init(UART_ADDR, &config);

    // configure the clock to use
    DL_UART_setClockConfig(UART_ADDR, &clk_config);

    // configure the baud rate
    DL_UART_configBaudRate(UART_ADDR, CPUCLK_FREQ, BAUD_RATE);

    // UART enable
    DL_UART_enable(UART_ADDR);

    // enable LEDs
    DL_GPIO_initDigitalOutput(LEDS_STATUS_LED_IOMUX);
    DL_GPIO_setPins(GPIOB, LEDS_STATUS_LED_PIN);
    DL_GPIO_enableOutput(GPIOB, LEDS_STATUS_LED_PIN);
    STATUS_LED_ON();
}

void _exit(int status) {
    while(1);  // no exit on the real device
}

int _read(int fd, char *buf, int len) {
    // TODO: read from UART0
    return len;
}

int _write(int fd, char *buf, int len) {
    for (int i = 0; i < len; i++) {
        // turn on LED while transmitting
        // STATUS_LED_ON();
        DL_UART_transmitDataBlocking(UART_ADDR, buf[i]);
        // STATUS_LED_OFF();
    }
    return len;
}

void _fini(void) {}
void _init(void) {}
