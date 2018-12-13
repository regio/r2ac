const int MOST_NO_OF_DIGITS = 10;

#include "rsa.h"
#include "aes.h"
#include <string.h>
#include "sha256.h"
//long *AES_Key;
unsigned char AES_Key[33] = "PATASDEGALINHA2017CHAPOLIN123456";
unsigned char ptext[100] = "You with your switching sides and your walk-by lies and humiliation", *ctext, *ctext2; 
unsigned char ptext2[100] = "You with your switching sides and your walk-by lies and humiliation"; 

//int FINAL_LENGTH = size_string(ptext);
int FINAL_LENGTH=99;
unsigned char AES_Key_uc[178];
int i=0;
long tempo_inicial;
long tempo_final;
uint8_t *hash;

void setup() {

  Serial.begin(115200);
 
}

void loop() {
  AES_Key[32] = '\0';

  AES_Key_uc[176]='\0';
  for (i = 0; i < 32; ++i) {
    AES_Key_uc[i] = AES_Key[i];
  }
  
  tempo_inicial=micros();
  Sha256.init();
  Sha256.print((char *) ptext2);
  hash = Sha256.result();

  //Serial.println("antes de encriptar");

  ctext = ECB_AES_encrypt(ptext, AES_Key_uc, FINAL_LENGTH);
  ctext2 = ECB_AES_encrypt(hash, AES_Key_uc, FINAL_LENGTH);

  tempo_final = micros();
  Serial.print("Tempo total: ");
  Serial.println(tempo_final - tempo_inicial);
  ctext = ECB_AES_decrypt(ctext, AES_Key_uc);
  
  for (i = 0; i < 99; ++i) {
    Serial.write(ctext[i]);
        delay(1);
  }
}


