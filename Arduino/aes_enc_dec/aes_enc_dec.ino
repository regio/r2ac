const int MOST_NO_OF_DIGITS = 10;

#include "rsa.h"
#include "aes.h"
#include <string.h>
//long *AES_Key;
unsigned char AES_Key[33] = "PATASDEGALINHA2017CHAPOLIN123456";
unsigned char ptext[100] = "You with your switching sides and your walk-by lies and humiliation", *ctext; 
int FINAL_LENGTH = size_string(ptext);
unsigned char AES_Key_uc[178];
int i=0;
long tempo_inicial;
long tempo_final;
void setup() {

  Serial.begin(115200);
 
}

void loop() {

  
  AES_Key[32] = '\0';

  AES_Key_uc[176]='\0';
  for (i = 0; i < 32; ++i) {
    AES_Key_uc[i] = AES_Key[i];
  }
  //Serial.println("antes de encriptar");

  ctext = ECB_AES_encrypt(ptext, AES_Key_uc, FINAL_LENGTH);

  //Serial.println("depois de encriptar");
  //for (i = 0; i < FINAL_LENGTH; ++i) {
    //Serial.write(to_string(ctext[i]));
  //}
 
  //Serial.println("antes de decriptar");
  /*
  tempo_inicial= micros();
  */  
  ctext = ECB_AES_decrypt(ctext, AES_Key_uc);
  tempo_final = micros();
  /*
  Serial.print("Tempo total: ");
  Serial.println(tempo_final - tempo_inicial);
  
  for (i = 0; i < FINAL_LENGTH; ++i) {
    Serial.write(ctext[i]);
        delay(100);
  }
  Serial.println("depois de decriptar");
  */
  //delay(10000);
}

