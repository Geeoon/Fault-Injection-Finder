#include <errno.h>

#include <ti/devices/msp/msp.h>
#include <ti/driverlib/driverlib.h>
#include <ti/driverlib/m0p/dl_core.h>

#define POWER_STARTUP_DELAY             (16)
#define CPUCLK_FREQ                     32000000

// change UART here
#define UART_ADDR                       (UART_Regs*)UART0_BASE 
#define BAUD_RATE                       115200

<<<<<<< Updated upstream
#define LED3_PORT   GPIOA
#define LED3_PIN    DL_GPIO_PIN_0
// #define LED3_PIN    LD_GPIO_PIN_10
#define LED3_IOMUX  IOMUX_PINCM1   // PA0 = PINCM1 on MSPM0L2228
// #define LED3_IOMUX  IOMUX_PINM25
=======
#define LEDS_PORT                       (GPIOB)
#define LEDS_STATUS_LED_PIN             (DL_GPIO_PIN_14)
#define LEDS_STATUS_LED_IOMUX           (IOMUX_PINCM35)
>>>>>>> Stashed changes

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

    // LED configuration
    DL_GPIO_reset(LED3_PORT);
    DL_GPIO_enablePower(LED3_PORT);
    delay_cycles(POWER_STARTUP_DELAY);

    DL_GPIO_initDigitalOutput(LED3_IOMUX);
    DL_GPIO_clearPins(LED3_PORT, LED3_PIN);

    DL_GPIO_setUpperPinsPolarity(LED3_PORT, 0);
    DL_GPIO_enableOutput(LED3_PORT, LED3_PIN);
    DL_GPIO_clearPins(LED3_PORT, LED3_PIN);  // GPIO low
}

void _exit(int status) {
    while(1);  // no exit on the real device
}

int _read(int fd, char *buf, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] = (char)DL_UART_receiveDataBlocking(UART_ADDR);
    }
    return len;
}

int _write(int fd, char *buf, int len) {
    for (int i = 0; i < len; i++) {
        DL_UART_transmitDataBlocking(UART_ADDR, buf[i]);
    }
    return len;
}

void led_blip(void) {
    DL_GPIO_setPins(LED3_PORT, LED3_PIN);  // GPIO PA0 high
    delay_cycles(5);
    DL_GPIO_clearPins(LED3_PORT, LED3_PIN);  // GPIO PA0 low
}

void _fini(void) {}
void _init(void) {}
