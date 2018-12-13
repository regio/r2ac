#include "sha256.h"
unsigned long StartTime, CurrentTime,ElapsedTime;
void setup(){
  Serial.begin(115200);
  
}

void loop(){
  StartTime=micros();  
  uint8_t *hash;
  Sha256.init();
  Sha256.print("You with your switching sides and your walk-by lies and humiliation");
  hash = Sha256.result();
  CurrentTime=micros();
  ElapsedTime=CurrentTime-StartTime;
  Serial.print("Tempo: ");
  Serial.println(ElapsedTime);
  
  delay (5000);
  for (int i=0;i<32;i++){
    Serial.print(hash[i]);
    Serial.print(" ");
  }
  Serial.println();
  
}
