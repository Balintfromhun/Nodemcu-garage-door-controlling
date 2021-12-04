#ifdef DEBUG_ESP_PORT
#define DEBUG_MSG(...) DEBUG_ESP_PORT.printf( __VA_ARGS__ )
#else
#define DEBUG_MSG(...)
#endif

#include <Arduino.h>
#include <uECC.h>
extern "C"{
  #include <espnow.h>
}
#include "EEPROM.h"
#include <ESP8266WiFi.h>
#include <ESP8266TrueRandom.h>
#include "ChaCha.h"
#include "EEPROM.h"
#include "stack"
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <CRC32.h>

//The mac address of the 2 device:
//uint8_t ADDR1[6]={0xE8, 0xDB, 0x84, 0xE1, 0x31, 0xE0};
//uint8_t ADDR2[6]={0xE8, 0xDB, 0x84, 0xE0, 0xE3, 0x57};


// Definitions----------------------------------------------------------------

#define DEVICE_NUMBER 3
#define CIPHER_SIZE 64
#define MSG_PRE_SIZE 11
#define CS_SIZE 4
#define inc 8
#define REFRESH_RATE 1000 //ms
#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels
#define SCREEN_ADDRESS 0x3C ///< See datasheet for Address; 0x3D for 128x64, 0x3C for 128x32
#define CHR_MSG_RATE 100


// OLED display --------------------------------------------------------------

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire);

// Structures ----------------------------------------------------------------

// Communication structure
typedef struct {
  uint8_t id;
  String name;
  uint8_t MAC_addr[6];
  uint8_t private_key[16];
  bool CR_State = false;
} deviceInfo;

//Key-value pairs
typedef struct{
  uint16_t key;
  uint32_t value;
} key_value_struct;

// Devices-------------------------------------------------------------------------------

// Not specified for the real device


deviceInfo Devices[3] =
  {
    {1, "Device: Remote controller", {0xE8, 0xDB, 0x84, 0xE1, 0x31, 0xE0}, {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x10,0x11,0x12,0x13,0x14,0x15,0x16} },
    {2, "Device: Control panel", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} , {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x10,0x11,0x12,0x13,0x14,0x15,0x16} },
    {3, "Device: Garage door", {0xE8, 0xDB, 0x84, 0xE0, 0xE3, 0x57} ,{0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x10,0x11,0x12,0x13,0x14,0x15,0x16} }
  };


deviceInfo Device_self = Devices[ 2 ] ;


// Flags---------------------------------------------------------------------------------

bool MSG_RECV = false;
bool REQ_SEND = false;

// Comm variables-------------------------------------------------------------------------

// Broadcast to 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF for all device
uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t recivedMessage[CIPHER_SIZE];

// The Size of the Message + 4 is the Checksum at the end, sizeof(uint16_t)
const size_t MSG_SIZE = MSG_PRE_SIZE + CIPHER_SIZE + CS_SIZE;

// Buffers---------------------------------------------------------------------------------

uint8_t BUFFER_COMMREC[MSG_SIZE];
uint8_t BUFFER_COMMSEND[CIPHER_SIZE];
uint8_t BUFFER_DECRYPT[CIPHER_SIZE];

// Chacha parameters------------------------------------------------------------------------

ChaCha commCrypt;
uint8_t IV[8];
uint8_t counter[8]={1,2,3,4,5,6,7,8};
uint8_t number_rounds = 5;
size_t keysize = 8;

// All purpose variables-------------------------------------------------------------------

//Buffer, mainly used for communication
uint8_t BUFFER[MSG_SIZE];


// Device variables------------------------------------------------------------------------

uint8_t CMDN = 0;

// CRC ------------------------------------------------------------------------------------


//Key-value pairs--------------------------------------------------------------------------

enum key_keypair : uint16_t {
  led_1 = 0x0001,
  led_2 = 0x0002,
  Chr_req = 0xff00,
  Chr_give = 0x00ff,
  Chr_resp = 0x0f0f,
  Chr_judge = 0xf0f0,
  Stop_comm = 0x1010
  };

enum value_keypair : uint32_t {
  turn_on = 0x80000000,
  turn_off = 0x00000000,
  ChR_OK = 0xffff0000,
  ChR_NOK = 0x0000ffff,
  ChR_R = 0xf0f0f0f0
};


// Functions ------------------------------------------------------------------------------

// Communication sending callback function - uecc
void onSent(uint8_t *mac_addr, uint8_t sendStatus) {
  REQ_SEND=false;
  Serial.println("Message sent!");
}

// Communication Recive buffer
void onRecive(uint8_t* mac, uint8_t* incomingData, uint8_t len){
if(MSG_RECV == false)
{
  memcpy(BUFFER_COMMREC, incomingData, MSG_SIZE);
  MSG_RECV = true;
}
}

//reset chacha cipher
void chachareset_send(uint8_t id){
  commCrypt.setKey(Devices[id-1].private_key, keysize);
  commCrypt.setIV(IV, commCrypt.ivSize());
  commCrypt.setCounter(counter, 8);
}

void chachareset_recive(){
  commCrypt.setKey(Device_self.private_key, keysize);
  commCrypt.setIV(IV, commCrypt.ivSize());
  commCrypt.setCounter(counter,8);
}

//ESP-NOW communication init
void espnowInit(){
  
  if(esp_now_init()) Serial.println("ESP-NOW initialization failed");

  esp_now_register_send_cb(onSent);
  esp_now_register_recv_cb(onRecive);
  esp_now_set_self_role(ESP_NOW_ROLE_COMBO);



  WiFi.mode(WIFI_STA);
}

// crypts TBC to itself
void chachacrypt(uint8_t id, uint8_t* TBC){

  chachareset_send(id);
  size_t posn, len;
  for(posn = 0; posn < CIPHER_SIZE; posn += inc){
    len = CIPHER_SIZE - posn;
    if(len > inc)
    len = inc;
    commCrypt.encrypt(TBC + posn, TBC + posn, len);
  }
}

//ChaCha init
void chachainit(){

  commCrypt.clear();
  commCrypt.setKey(Device_self.private_key , keysize);
  commCrypt.setIV(IV, commCrypt.ivSize());
  commCrypt.setCounter(counter,8);
  commCrypt.setNumRounds(number_rounds);
  
}

//Constructs the message to be sent, in the buffer
void construct_commsend(uint8_t target_id, key_value_struct* commands, uint8_t numb_commands){
  CRC32 crc;
  uint8_t cmdtosend_numb = 1;
  if(numb_commands>CIPHER_SIZE/8) cmdtosend_numb = CIPHER_SIZE/8;
  else{
    cmdtosend_numb = numb_commands;
  }

  memset(BUFFER,0,sizeof(BUFFER));
  BUFFER[0] = Device_self.id;
  BUFFER[1] = target_id;

  uint8_t randomIV[8];
  for(int i = 0; i < 8; i++){
    randomIV[i] = (uint8_t)ESP8266TrueRandom.randomByte();
  }

  memcpy(IV, randomIV, 8);
  memcpy(BUFFER + 2 , IV , sizeof(IV));
  memcpy(BUFFER + 2 + sizeof(IV), &cmdtosend_numb, 1);
  memset(BUFFER_COMMSEND, 0, CIPHER_SIZE);

  for(int i=0; i < cmdtosend_numb; i++){
    memcpy(BUFFER_COMMSEND + i*sizeof(commands[i]), (uint16_t*)&commands[i], sizeof(commands[i]));
  }

  chachacrypt(target_id, BUFFER_COMMSEND);

  memcpy(BUFFER + MSG_PRE_SIZE, BUFFER_COMMSEND , CIPHER_SIZE);

  
  for(int i=0; i < MSG_SIZE - CS_SIZE; i++){
    crc.update(BUFFER[i]);
  }
  uint32_t  cs = 0;
  cs = crc.finalize();

  memcpy(BUFFER+MSG_SIZE - CS_SIZE, (uint8_t *) &cs, CS_SIZE);
  crc.reset();
}

// Checking the checksum of the message, if the checksum is good, the return value is true
bool checkChecksum(uint8_t* data, uint32_t csRec){
  CRC32 crc_temp;
  for(int i=0; i < MSG_SIZE - CS_SIZE; i++){
    crc_temp.update(data[i]);
  }
  uint32_t cs_temp = crc_temp.finalize();
  bool ret_value = false;
  if (csRec == cs_temp)
    ret_value = true;
  else
    ret_value = false;
  return ret_value;
  crc_temp.reset();

}

void print_errormsg(uint8_t err_msg){
  switch (err_msg)
  {
  case 0b01000000:
    display.print("Checksum is not okay!");
    break;
  
  default:
    break;
  }
  display.display();
}

//for testing
void chachadecrypt_test(uint8_t* TBDC){

  chachareset_send(1);
  size_t posn, len;
  
  for (posn = 0; posn < CIPHER_SIZE; posn += inc) {
  len = CIPHER_SIZE - posn;
    if (len > inc)
        len = inc;
    commCrypt.decrypt(TBDC + posn, TBDC + posn, len);
    }
  
}

// It will decrypt the TBDC to itself
void chachadecrypt(uint8_t* TBDC){

  chachareset_recive();
  size_t posn, len;
  
  for (posn = 0; posn < CIPHER_SIZE; posn += inc) {
  len = CIPHER_SIZE - posn;
    if (len > inc)
        len = inc;
    commCrypt.decrypt(TBDC + posn, TBDC + posn, len);
    }
  
}

// Sends crypted data to the target id device
void send_chacha(uint8_t target_device, key_value_struct* cmd, uint_fast8_t numb_cmds){

  construct_commsend(target_device, cmd, numb_cmds);
  esp_now_send(BROADCAST, BUFFER, sizeof(BUFFER));

  // esetleges állapotvisszajelzés, hogy elment-e az adat
}


// Function to run when a message arrives
uint8_t msg_rec(){
  uint8_t out = 0b00000000;
  uint8_t temp[MSG_SIZE];
  memset(recivedMessage, 0, CIPHER_SIZE);
  memcpy(temp, BUFFER_COMMREC, MSG_SIZE);
  memcpy(IV, temp +  2, sizeof(IV));
  memcpy(BUFFER_DECRYPT, temp + MSG_PRE_SIZE, CIPHER_SIZE);
  chachadecrypt(BUFFER_DECRYPT);
  memcpy(recivedMessage, BUFFER_DECRYPT, CIPHER_SIZE);
  CMDN = temp[10];
  uint32_t csRec;
  memcpy((uint8_t *) &csRec, temp + MSG_SIZE - CS_SIZE, CS_SIZE) ;
  uint8_t CS_CHECK[MSG_SIZE-CS_SIZE];
  memcpy(CS_CHECK, temp, MSG_SIZE-CS_SIZE);
  bool boolTemp = checkChecksum(CS_CHECK, csRec);
  if(!boolTemp)
    {out = out | 0b10000000;}
  MSG_RECV = false;

  return out;
}

// What to do with the recived data
void Jobtodo(uint8_t* MIXED, uint8_t numb, uint8_t target){
  display.clearDisplay();
  display.setCursor(0,10);
  display.print("Msg sent from:");
  display.println(BUFFER_COMMREC[0]);
  key_value_struct temp[numb];

  for(int i=0; i<numb; i++)
  {
    memcpy(&temp[i],MIXED+i*sizeof(key_value_struct),sizeof(key_value_struct));
  }

  for(int i=0; i<numb; i++){
    Serial.print("Key value:");
    Serial.println(temp[i].key,HEX);
    Serial.print("Value value:");
    Serial.println(temp[i].value,HEX);
    switch (temp[i].key)
    {
    case Stop_comm:
      Devices[target].CR_State = false;
      Serial.print("Stopped communication \nwith device:");
      Serial.println(target);
      display.clearDisplay();
      display.setCursor(0,10);
      display.print("End Comm: ");
      display.println(target);
      display.display();
      break;
    
    default:
      break;
    }
  }

}



void MSG_process()
{
if(MSG_RECV)
{
  MSG_RECV = false;
  uint8_t msg_from = BUFFER_COMMREC[0];
  uint8_t error_msg = msg_rec();
  
  // Check if the message was for this device
  if(Device_self.id == BUFFER_COMMREC[1])
  {
    // Check if the device is allowed to speak
    if( Devices[msg_from].CR_State == true )
    {
      
      uint32_t temp_cs = 0;
      memcpy((uint8_t*)&temp_cs, BUFFER_COMMREC+MSG_SIZE - CS_SIZE, CS_SIZE);

      // Not necessary
      print_errormsg(error_msg);

      Jobtodo(recivedMessage, CMDN, msg_from);

      display.print("Error msg:");
      display.println(error_msg, BIN);
      display.display();
    }
    else
    {
      Serial.println("Something arrived, with no authentication!");
      key_value_struct in_chr;
      memcpy(&in_chr,recivedMessage,sizeof( key_value_struct ));
      switch (in_chr.key)
      {
      case Chr_req:
        Serial.println("Got a challenge request");
        key_value_struct chr_c;
        chr_c.key = Chr_give;
        send_chacha(msg_from,&chr_c,1);
        break;
      case Chr_resp:
        Serial.println("Got a challenge response");
        if(in_chr.value == ChR_R)
        {
          key_value_struct chr_c;
          chr_c.key = Chr_judge;
          chr_c.value = ChR_OK;
          send_chacha(msg_from, &chr_c, 1);
          Devices[msg_from].CR_State = true;
        }
        else
        {
          key_value_struct chr_c;
          chr_c.key = Chr_judge;
          chr_c.value = ChR_NOK;
          send_chacha(msg_from, &chr_c, 1);
        }
        break;
      default:
        MSG_RECV = false;
        break;
      }

    }
    
  }
  else
  {
    // What to do, if the message is not for this fevice
    MSG_RECV = false;
    display.clearDisplay();
    display.setCursor(0,10);
    display.println("Message recived, but it's not for this \n device!");
    display.display();
  }

}
}

void turn_led_msg(uint8_t target_id){
  key_value_struct turn_led = {led_1,turn_on};
  send_chacha(target_id, &turn_led, 1);
  display.clearDisplay();
  display.setCursor(0,10);
  display.print("Message sent! \nTurn led 1\nOn device:");
  display.println(target_id);
  display.display();
}

void turn_all_led(uint8_t target_id){
  key_value_struct turn_led[2] = {{led_1,turn_on}, {led_2,turn_on}};
  send_chacha(target_id, turn_led, 2);
  display.clearDisplay();
  display.setCursor(0,10);
  display.print("Message sent! \nTurn led 1/2 \nOn device:");
  display.println(target_id);
  display.display();
}

void Comm_send_start(uint8_t target)
{
  bool response=false;
  bool TOUT=false;
  uint8_t TOUT_counter = 0;

  key_value_struct chr_keypair;
  chr_keypair.key = Chr_req;
  unsigned long timeStarted = millis();
  send_chacha(target, &chr_keypair, 1);
  

  while((!response) && (!TOUT))
  {
    /* Start of Challenge response loop */
    TOUT_counter++;
    if(MSG_RECV)
    {
      /* Start of MSG recv */
      uint8_t msg_from = BUFFER_COMMREC[0];
      if(msg_from == target)
      {
        msg_rec();
        key_value_struct cr_check;
        memcpy(&cr_check, recivedMessage,sizeof(key_value_struct));
        switch (cr_check.key)
        {
        case Chr_give:
          key_value_struct cr_give;
          cr_give.key = Chr_resp;
          cr_give.value = ChR_R;
          send_chacha(target,&cr_give,1);
          break;
        case Chr_judge:
          if (cr_check.value == ChR_OK)
          {
            Devices[target].CR_State = true;
            response=true;
          }
          else
          {
            Devices[target].CR_State=false;
            Serial.println("CHR not OK");
            response = true;
          }
          break;
        default:
          response = true;
          Serial.print("CHR key:");
          Serial.println(cr_check.key,HEX);
          Serial.println("Not recognised key");
          break;
        }

      }
      else
      {
        /* Do nothing */
      }

      MSG_RECV = false;
      /* End of MSG recv */
    }
    else
    {
      /* Do nothing */
    }
    if(TOUT_counter > 100 )
    {
      Serial.println("Time out, Challenge response failed");
      TOUT = true;
    }
    else
    {
      /* Do nothing */
    }
    // Loop rate
    delay(CHR_MSG_RATE);

    /* End of Challenge response loop */
  }
  if(!TOUT)
  {
    unsigned long timeStopped = millis();
    unsigned long timePassed = timeStopped - timeStarted;
    Serial.print("Challenge response time: ");
    Serial.print(timePassed);
    Serial.println(" ms");
  }
  
  return;
  /* End of function */
}

void Comm_send_end(uint8_t target)
{
  key_value_struct stopCommMsg;
  stopCommMsg.key = Stop_comm;
  send_chacha(target, &stopCommMsg, 1);
}

void comm_send_led(uint8_t target){
  if(!Devices[target].CR_State){
    Comm_send_start(target);
  }
  else{
    turn_all_led(target);
  }
}

//Setup function, runs after reset or booting
void setup() {

  //Serial monitoring
  Serial.begin(115200);

  //Communication init
  espnowInit();

  //ChaCha initialization
  chachainit();

  // LED display
  if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println("SSD1306 allocation failed");
  }
  Serial.println("Setup finished!");

  display.setTextSize(1);
  display.setCursor(0,10);
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.println("Setup finished!");
  display.println("Device id:");
  display.println(Device_self.id);
  display.display();

  
}

uint8_t send_counter = 0;

//Constantly running block

// Testing
void loop()
{
if(Device_self.id == 1 && send_counter < 2){
  comm_send_led(3);
  delay(2000);
  Comm_send_end(3);
  send_counter ++;
}
// Test end

// Checking the mailbox and process the data
MSG_process();


// End of the loop, refresh rate
delay(REFRESH_RATE);

}
