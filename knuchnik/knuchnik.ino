/*******************************************************************
 * True Random Number Generator (TRNG) v2.5 - mbedtls AES-CBC
 *
 * This version replaces simple AES libraries with the robust,
 * standard mbedtls library included with the ESP-IDF.
 * It uses the more secure AES-128-CBC mode with PKCS7 padding.
 *******************************************************************/

// --- Core Libraries ---
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h> // Using SH110X for 1.3" OLED
#include "I2Cdev.h"
#include "MPU6050.h"
#include <Adafruit_SSD1306.h>
#include <QRCodeGenerator.h>


// --- Cryptography Library ---
#include <mbedtls/aes.h>

// --- Networking Libraries ---
#include "tcp.ino"

#define BUTTON_UP     5
#define BUTTON_DOWN   17
#define BUTTON_SELECT 16
#define GATE_CONTROL_PIN 27
#define COUNTER_RESET_PIN 26
const int counterPins[8] = {35, 32, 33, 25, 26, 27, 14, 12};

// --- Display & MPU Setup ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
#define QR_SCALE 2
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
MPU6050 mpu;

// --- Main Menu Configuration ---
const int MENU_ITEMS_COUNT = 4;
const char* menuItems[MENU_ITEMS_COUNT] = {
  "Generate Password", "Set Length", "Set Complexity", "About"
};

// --- State Variables ---
int8_t selector = 0;
int8_t top_line_index = 0;
long lastDebounceTime = 0;
long debounceDelay = 200;
#define MIN_PASSWORD_LEN 4
#define MAX_PASSWORD_LEN 32

// - Toggling display -
static bool screenOn = true;
unsigned long buttonPressStartTime = 0;
static bool buttonHeld = false;

// --- Networking variables & conditions ---
static bool ap_enabled = false;
esp_netif_ip_info_t ip_info;

// -- IP address configuration ---
#define AP_IP_ADDR 192, 168, 1, 4
#define AP_GW_ADDR 192, 168, 1, 1
#define AP_NETMASK 255, 255, 255, 255

// --- Password Generation Settings ---
static int passwordLength = 16;
enum Complexity {  NUMBERS_ONLY, NUMBERS_LOWER, LOWER_UPPER_NUM, ALL_CHARS  };
static uint8_t complexityLevel = ALL_CHARS;
const char* complexityNames[] = {
  "Numbers", "Lowercase", "Uppercase", "Letters", "Alphanumeric", "All Symbols"
};
static byte randomBytes[MAX_PASSWORD_LEN * 16];

// --- Cryptography ---
#define KEY_SIZE 16
#define BLOCK_SIZE 16
// This is the fixed key used to encrypt the random data
const unsigned char encryptionKey[KEY_SIZE] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};
// This is the fixed IV for CBC mode. MUST match the one in the Rust app.
const unsigned char iv[BLOCK_SIZE] = {
    0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte generatedKey[KEY_SIZE];

/* FUNCTION DEFINITION */
void setup();
void loop();
size_t applyPadding(const uint8_t*, size_t, uint8_t*);
void encrypt_cbc(uint8_t*, size_t, const uint8_t*, uint8_t*, uint8_t*);
byte readCounter();
byte generateRandomByte();
void runPasswordGeneration(uint8_t complexity);
String filter_password(byte, uint8_t, uint8_t, byte*);
void do_action_up();
void do_action_down();
void handleLocalInput();
void drawMenu();
void performAction();
void chooseLength();
void chooseComplexity();
void displayAbout();
void tcpSendMessage(char*);
esp_err_t wifiInitAP(void);
static void wifi_event_handler(void*, esp_event_base_t, int32_t, void*);
static void tcp_server_task(void *);
uint8_t generateQR(char text[32]);
void displayQR(uint8_t qr);

/*========================================================================*/
/* SETUP                                                                  */
/*========================================================================*/

void setup() {
  Serial.begin(115200);
  Wire.begin(); // Default I2C pins for ESP32 are 21 (SDA), 22 (SCL)

  pinMode(BUTTON_UP, INPUT_PULLUP);
  pinMode(BUTTON_DOWN, INPUT_PULLUP);
  pinMode(BUTTON_SELECT, INPUT_PULLUP);
  pinMode(GATE_CONTROL_PIN, OUTPUT);
  pinMode(COUNTER_RESET_PIN, OUTPUT);
  digitalWrite(GATE_CONTROL_PIN, LOW);

  for (int i = 0; i < 8; i++) {
    pinMode(counterPins[i], INPUT);
  }

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SH1106 allocation failed"));
    for (;;);
  }

  mpu.initialize();
  if (!mpu.testConnection()) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SH110X_WHITE);
    display.setCursor(0, 0);
    display.println("MPU6050 Failed!");
    display.display();
    for (;;);
  }

//  wifiInitAP();

  //xTaskCreate(tcp_server_task, "tcp_server", 4096, NULL, 5, NULL);
}

/*========================================================================*/
/* MAIN LOOP                                                              */
/*========================================================================*/
void loop() {
  handleLocalInput();
  drawMenu();
}

/*========================================================================*/
/* CRYPTOGRAPHY HELPER FUNCTIONS                                          */
/*========================================================================*/

/**
 * @brief Applies PKCS7 padding to the input data.
 * @param input The data to pad.
 * @param inputLen The length of the input data.
 * @param output Buffer to store the padded data.
 * @return The new length of the data after padding.
 */
size_t applyPadding(const uint8_t* input, size_t inputLen, uint8_t* output) {
  size_t paddedLen = ((inputLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
  memcpy(output, input, inputLen);
  uint8_t padValue = paddedLen - inputLen;
  for (size_t i = inputLen; i < paddedLen; i++) {
    output[i] = padValue;
  }
  return paddedLen;
}

/**
 * @brief Encrypts data using AES-128-CBC with mbedtls.
 * @param input The plaintext data to encrypt.
 * @param len The length of the plaintext data.
 * @param key The 16-byte encryption key.
 * @param iv The 16-byte initialization vector.
 * @param output Buffer to store the ciphertext.
 */
void encrypt_cbc(uint8_t* input, size_t len, const uint8_t* key, uint8_t* iv_local, uint8_t* output) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, KEY_SIZE * 8);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_local, input, output);
  mbedtls_aes_free(&aes);
}


/*========================================================================*/
/* CORE TRNG & NETWORKING LOGIC                                           */
/*========================================================================*/


/* On call, read data from counter */
byte readCounter() {
  byte value = 0;
  for (int i = 0; i < 8; i++) {
    if (digitalRead(counterPins[i]) == HIGH) {
      value |= (1 << i);
    }
  }
  return value;
}


/* Using the readCounter() function, read a byte after a randomised amount of time. */
byte generateRandomByte() 
{
  int16_t ax, ay, az, gx, gy, gz;
  digitalWrite(COUNTER_RESET_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(COUNTER_RESET_PIN, LOW);

  unsigned long startTime = millis();
  while (millis() - startTime < 200) {
    mpu.getMotion6(&ax, &ay, &az, &gx, &gy, &gz);
    long motionEnergy = abs(ax) + abs(ay) + abs(az) + abs(gx) + abs(gy) + abs(gz);
    unsigned long gateTime = (motionEnergy % 100) + 10;
    digitalWrite(GATE_CONTROL_PIN, HIGH);
    delayMicroseconds(gateTime);
    digitalWrite(GATE_CONTROL_PIN, LOW);
    delayMicroseconds(10);
  }
  return readCounter();
}



/* Returns a password based on complexity level. */
String filter_password(byte *key, uint8_t complexity, byte *randomBytes)
{
  String filtered = "";
  String pass = String((char*)key);
  for (uint8_t i = 0; i < passwordLength; i++) {
    char c = pass[i];
    bool included = false;

    if ( (complexity == NUMBERS_ONLY && isdigit(c)
      || (complexity == NUMBERS_LOWER && (isdigit(c) || (c >= 'a' && c <= 'z')))
      || (complexity == LOWER_UPPER_NUM && (isdigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
      || (complexity == ALL_CHARS && c >= 33 && c <= 126))) // all printable ASCII characters
      included = true;
    
    if (included) filtered += c;
  }
  // pad password with extra characters
  for (uint8_t i = 0; i < (pass.length() - filtered.length()); i++) {
    byte rnd = generateRandomByte();
    delayMicroseconds(20);
    switch (complexity) {
      case NUMBERS_ONLY: filtered += (char)('0' + (generateRandomByte() % 10)); break;
      case NUMBERS_LOWER: filtered += (char)('a' + (generateRandomByte() % 26)); break;
      case LOWER_UPPER_NUM: filtered += (char)('A' + (generateRandomByte() % 26)); break;
      // After my death, I will be going to C programmer hell
      case ALL_CHARS: filtered += "!@#$%^&*()_+-=[]{}|;:,.<>?"[generateRandomByte() % String("!@#$%^&*()_+-=[]{}|;:,.<>?").length()]; break;
    }
  }
  return filtered;
}

void runPasswordGeneration(uint8_t complexity) {
  display.clearDisplay();
  display.setCursor(10, 5);
  display.print("Shaking device to");
  display.setCursor(25, 15);
  display.print("gather entropy...");
  display.display();

  // 1. Generate random bytes for password length
  for (int i = 0; i < passwordLength; i++) {
    generatedKey[i] = generateRandomByte();
    delayMicroseconds(20); // more randomness
  }
  for (int i = 0; i < MAX_PASSWORD_LEN * 4; i++) {
    randomBytes[i] = generateRandomByte();
    delayMicroseconds(20);
  }

  String password_string = filter_password(generatedKey, complexity, randomBytes);
  
  // 2. Pad the data. Since input is 16 bytes, output will be 32 bytes.
  uint8_t paddedData[32];
  size_t paddedLen = applyPadding(generatedKey, KEY_SIZE, paddedData);

  // 3. Encrypt the padded data
  uint8_t encryptedData[32];
  uint8_t iv_copy[BLOCK_SIZE]; // mbedtls modifies the IV, so we use a copy
  memcpy(iv_copy, iv, BLOCK_SIZE);
  encrypt_cbc(paddedData, paddedLen, encryptionKey, iv_copy, encryptedData);
 
  delay(2000);
  displayQR(password_string);
  /* also should send data to pc */
}



// --- UI AND MENU FUNCTIONS ---

void handleScreenToggle() 
{
  if (digitalRead(BUTTON_SELECT) == LOW) {
    if (!buttonHeld) {
      buttonPressStartTime = millis();
      buttonHeld = true;
    } else {
      // Check if button has been held for 5 seconds
      if (millis() - buttonPressStartTime >= 5000) {
        screenOn = !screenOn;
        if (screenOn) {
          display.ssd1306_command(SSD1306_DISPLAYON);
          display.clearDisplay();
          display.display();
        } else {
          display.ssd1306_command(SSD1306_DISPLAYOFF);
        }
        buttonHeld = false;
        // Wait for button release to avoid rapid toggling
        while (digitalRead(BUTTON_SELECT) == LOW) {
          delay(10);
        }
      }
    }
  } else {
    buttonHeld = false;
  }
}

void do_action_up() {
  selector--;
  if (selector < 0) selector = MENU_ITEMS_COUNT - 1;
  if (selector < top_line_index) top_line_index = selector;
}
void do_action_down() {
  selector++;
  if (selector >= MENU_ITEMS_COUNT) selector = 0;
  if (selector >= top_line_index + 3) top_line_index = selector - 2;
}
void handleLocalInput() {
  if ((millis() - lastDebounceTime) < debounceDelay) return;
  if (digitalRead(BUTTON_UP) == LOW) { do_action_up(); lastDebounceTime = millis(); }
  if (digitalRead(BUTTON_DOWN) == LOW) { do_action_down(); lastDebounceTime = millis(); }
  if (digitalRead(BUTTON_SELECT) == LOW) { performAction(); lastDebounceTime = millis(); }
}

void drawMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  for (int i = 0; i < 4; i++) {
    int item_index = top_line_index + i;
    if (item_index < MENU_ITEMS_COUNT) {
      display.setCursor(10, 5 + i * 10);
      display.print(menuItems[item_index]);
    }
  }
  int selector_y_pos = 5 + (selector - top_line_index) * 10;
  display.setCursor(0, selector_y_pos);
  display.print(">");
  display.display();
}

void performAction() {
  switch (selector) {
    case 0: runPasswordGeneration(complexityLevel);  break;
    case 1: chooseLength(); break;
    case 2: chooseComplexity(); break;
    case 3: displayAbout(); break;
  }
}
void chooseLength() {
  bool setting = true;
  delay(debounceDelay);
  while (setting) {
    if (digitalRead(BUTTON_UP) == LOW) { delay(debounceDelay); passwordLength++; if (passwordLength > MAX_PASSWORD_LEN) passwordLength = MIN_PASSWORD_LEN; } 
    if (digitalRead(BUTTON_DOWN) == LOW) { delay(debounceDelay); passwordLength--; if (passwordLength < MIN_PASSWORD_LEN) passwordLength = MAX_PASSWORD_LEN; }
    if (digitalRead(BUTTON_SELECT) == LOW) { setting = false; }
    display.clearDisplay();
    display.setCursor(0, 0); display.print("Set Length (8-64)");
    display.setCursor(0, 12); display.print("Up/Down=+1/-1 Sel=OK");
    display.setTextSize(2); display.setCursor(50, 25); display.print(passwordLength);
    display.setTextSize(1); display.display();
  }
  delay(200);
}

void chooseComplexity() {
  bool setting = true;
  int tempSelector = complexityLevel;
  int numComplexityLevels = sizeof(complexityNames) / sizeof(char*);
  delay(debounceDelay);
  while (setting) {
    if ((millis() - lastDebounceTime) > debounceDelay) {
      if (digitalRead(BUTTON_UP) == LOW) { tempSelector--; if (tempSelector < 0) tempSelector = numComplexityLevels - 1; lastDebounceTime = millis(); }
      if (digitalRead(BUTTON_DOWN) == LOW) { tempSelector++; if (tempSelector >= numComplexityLevels) tempSelector = 0; lastDebounceTime = millis(); }
      if (digitalRead(BUTTON_SELECT) == LOW) { complexityLevel = tempSelector; setting = false; lastDebounceTime = millis(); }
    }
    display.clearDisplay();
    display.setCursor(0, 0); display.print("Set Complexity");
    display.setCursor(0, 12); display.print("Up/Down=Change Sel=OK");
    display.setTextSize(1); display.setCursor(20, 25); display.print(complexityNames[tempSelector]);
    display.display();
  }
  delay(200);
}
void displayAbout() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print("TRNG v2.5");
  display.setCursor(0, 10);
  display.print("mbedtls AES-CBC");
  display.setCursor(0, 20);
  display.print("Press Select...");
  display.display();
  delay(500);
  while(digitalRead(BUTTON_SELECT) == HIGH);
}

esp_err_t wifiInitAP(void)
{
  // Initialise AP stack
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  esp_netif_t* p_netif = esp_netif_create_default_wifi_ap();

  // initialise IP address for p_netif interface
  esp_netif_ip_info_t if_info;
  IP4_ADDR(&if_info.ip, 192, 168, 1, 4);
  IP4_ADDR(&if_info.gw, 192, 168, 1, 1);
  IP4_ADDR(&if_info.netmask, 255, 255, 255, 0);

  ESP_ERROR_CHECK(esp_netif_dhcps_stop(p_netif)); /* stop previously running DHCP */
  ESP_ERROR_CHECK(esp_netif_set_ip_info(p_netif, &if_info));
  ESP_ERROR_CHECK(esp_netif_dhcps_start(p_netif));

  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
  
  // Create our wifi network
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg)); 

  // Get IP address of ESP32
  wifi_config_t wifi_config = {
    .ap = {
      .ssid = AP_SSID,
      .password = AP_PASSWD,
      .ssid_len = strlen(AP_SSID),
      .channel = WIFI_CHANNEL_1,
      .authmode = WIFI_AUTH_WPA2_PSK,
      .max_connection = 1,
    },
  };

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  esp_netif_ip_info_t ip_info;
  ESP_ERROR_CHECK(esp_netif_get_ip_info(p_netif, &ip_info));
  ESP_LOGI(TAG, "ESP32 IP:" IPSTR, IP2STR(&ip_info.ip));

  return ESP_OK;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}
  
void tcpSendMessage(char* msg)
{

  // Creating socket for TCP connection
  int16_t sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server_addr {
    .sin_family = AF_INET,
    .sin_port = htons(TCP_PORT),
  };
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
  listen(sock, 1);

  while(1) {
     struct sockaddr_in client_addr;
     socklen_t addr_len = sizeof(client_addr);
     // on each iteration, create a new client with new socket address
     int8_t client = accept(sock, (struct sockaddr*)&client_addr, &addr_len);

     // recieve messages from client
     send(client, msg, strlen(msg), 0);

     close(client);
     delay(50);
  }
}

// Show a centered qr code on screen and wait
void displayQR(String text)
{
  QRCode qr;
  uint8_t qrcodeData[qrcode_getBufferSize(2)];
  qrcode_initText(&qr, qrcodeData, 2, 0, text.c_str());


  uint8_t offsetX = (SCREEN_WIDTH - (qr.size * 2)) / 2;
  uint8_t offsetY = (SCREEN_HEIGHT - (qr.size * 2)) / 2;

  display.clearDisplay();
  for (uint8_t y = 0; y < qr.size; y++) {
    for (uint8_t x = 0; x < qr.size; x++) {
      if (qrcode_getModule(&qr, x, y)) {
        display.fillRect(offsetX + (x * QR_SCALE), offsetY + (y * QR_SCALE), 2, 2, WHITE);
      }
    }
  }
  display.display();
  delay(200);
  while(digitalRead(BUTTON_SELECT) == HIGH);
}