
long RSA_Own_Private_Key[2] = {5723, 3341};
long RSA_Own_Public_Key[2] = {5723, 5};
const int MOST_NO_OF_DIGITS = 10;
unsigned long StartTime, CurrentTime,ElapsedTime;

//teste de encriptacao/decriptacao simples RSA

  char ptext[100] = "You with your switching sides and your walk-by lies and humiliation", *ctext;
  long *rsa_encrypted;
  long *rsa_decrypted;
  long *ptext_converted;
  //int FINAL_LENGTH = size_string(ptext);
  int FINAL_LENGTH = strlen(ptext);
//

#include "rsa.h"
#include "aes.h"
#include <string.h>

/*
void cycle_arduino_to_PC(long *AES_Key) {
  unsigned char ptext[100] = "You with your switching sides and your walk-by lies and humiliation", *ctext;
  
  int FINAL_LENGTH = size_string(ptext);
  unsigned char AES_Key_uc[178];
  AES_Key_uc[176]='\0';
  for (int i = 0; i < 16; ++i) {
    AES_Key_uc[i] = AES_Key[i];
  }
  //TESTE ENCRIPTANDO RSA
  //
  //rsa_encrypt(ptext, RSA_Own_Private_Key, FINAL_LENGTH);
  ctext = ECB_AES_encrypt(ptext, AES_Key_uc, FINAL_LENGTH);
  delay(100);
  Serial.println(to_string(FINAL_LENGTH));
  
  for (int i = 0; i < FINAL_LENGTH; ++i) {
    Serial.println(ctext[i]);
  }
}
  
void cycle_PC_to_arduino(long* AES_Key) {
  unsigned char ctext[100], *ptext, AES_Key_uc[178];
  AES_Key_uc[176] = '\0';
  int length;
  char length_string[MOST_NO_OF_DIGITS + 1];
  Serial.readBytes(length_string, MOST_NO_OF_DIGITS);
  length_string[MOST_NO_OF_DIGITS] = '\0';
  length = to_num(length_string);
  int i;
  for (i = 0; i < length; ++i) {
    char num_str[4]; 
    Serial.readBytes(num_str, 3);
    num_str[3] = '\0';
    ctext[i] = to_num(num_str);
    Serial.println(ctext[i]);
  }
  ctext[i] = '\0';

  for (int j = 0; j < 16; ++j) {
    AES_Key_uc[j] = AES_Key[j]; 
  } 
  delay(1000); 
  ptext = ECB_AES_decrypt(ctext, AES_Key_uc);
//  Serial.println ("ptext imprimindo: ");
  //Serial.println (ptext);
  
   delay(9000); 
}

long* get_AES_Key() {
  long *AES_Key_Encrypted;
  long *AES_Key;
  AES_Key_Encrypted = new long[17];
  AES_Key_Encrypted[16] = '\0';
  for (int i = 0; i < 16; ++i) {
    char num_str[MOST_NO_OF_DIGITS + 1];
    num_str[MOST_NO_OF_DIGITS] = '\0';
    Serial.readBytes(num_str, MOST_NO_OF_DIGITS);
    AES_Key_Encrypted[i] = to_num(num_str);
  }
  AES_Key = rsa_decrypt(AES_Key_Encrypted, RSA_Own_Private_Key, 16);
  delete[] AES_Key_Encrypted;
  return AES_Key;
}
*/
void setup() {
  
  Serial.begin(115200);
//  Serial.write("TkSOzZU9Wd*!byau$U2a\n");


}

void loop() {

  rsa_encrypted = rsa_encrypt(ptext, RSA_Own_Public_Key);
  /*
  Serial.println("Texto Encriptado");
  for(int i=0; i<FINAL_LENGTH;i++){
    Serial.print((char *) rsa_encrypted[i]);
  }
  delay(1000);
  */
  StartTime=micros();
  rsa_decrypted = rsa_decrypt(rsa_encrypted, RSA_Own_Private_Key, FINAL_LENGTH);
  CurrentTime=micros();
  ElapsedTime=CurrentTime-StartTime;
  /*
  Serial.println("Texto Decriptado");
  for(int j=0; j<FINAL_LENGTH;j++){
      Serial.print((char *) rsa_decrypted[j]);
  }
  delay(1000);
  */
  
  Serial.print("Passou isso de segundos para enc/dec: ");
  Serial.println(ElapsedTime);
  ptext_converted=string2ascii_int_list(ptext);
  for(int k=0; k<FINAL_LENGTH;k++){
      if(rsa_decrypted[k]!=ptext_converted[k]){
        Serial.println("FODEU!!!!!!!!!");
        break;
      }
      if(k==FINAL_LENGTH-1){
          Serial.println("Brilha Brilha Estrelinha");
      }
  }
  Serial.println("----------");
  delay(5000);
}


