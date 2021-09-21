#include <Arduino.h>
#include <uECC.h>
#include <espnow.h>
#include <ESP8266WiFi.h>
#include <ESP8266TrueRandom.h>

static int RNG(uint8_t *nrbyte, unsigned size) {
  
  *nrbyte=ESP8266TrueRandom.randomByte();
  return 1;
}

void setup() {
  Serial.begin(115200);
  Serial.println(WiFi.macAddress());
  uECC_set_rng(&RNG);
  
}



void loop() {
  const struct uECC_Curve_t * curve = uECC_secp160r1();
  uint8_t private1[21];
  uint8_t private2[21];
  
  uint8_t public1[40];
  uint8_t public2[40];
  
  uint8_t secret1[20];
  uint8_t secret2[20];
  
  unsigned long a = millis();
  uECC_make_key(public1, private1, curve);
  unsigned long b = millis();
  
  Serial.print("Made key 1 in "); Serial.println(b-a);
  a = millis();
  uECC_make_key(public2, private2, curve);
  b = millis();
  Serial.print("Made key 2 in "); Serial.println(b-a);

  a = millis();
  int r = uECC_shared_secret(public2, private1, secret1, curve);
  b = millis();
  Serial.print("Shared secret 1 in "); Serial.println(b-a);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  a = millis();
  r = uECC_shared_secret(public1, private2, secret2, curve);
  b = millis();
  Serial.print("Shared secret 2 in "); Serial.println(b-a);
  if (!r) {
    Serial.print("shared_secret() failed (2)\n");
    return;
  }
    
  if (memcmp(secret1, secret2, 20) != 0) {
    Serial.print("Shared secrets are not identical!\n");
  } else {
    Serial.print("Shared secrets are identical\n");
  }
  
}
