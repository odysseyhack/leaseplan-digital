
// undefine functions that the MKR GSM defines confliciting defintions for
#undef max
#undef min

#include "arduino_secrets.h"

// general libraries
#include <stdio.h>
#include <string>

// Arduino specific libraries
#include <MKRGSM.h>
#include <Wire.h>
#include <ACROBOTIC_SSD1306.h>

// Ethereum specific libraries
extern "C" {
#include "libs/crypto/ecdsa.h"
#include "libs/crypto/bignum256.h"
}
#include <keccak256.h>
#include <ethers.h>
#include "TX.h"
#include "RLP.h"
#include "keccak256.h"

using namespace std;

#define HASH_LENGTH 32
#define SIGNATURE_LENGTH 64
#define BUTTON_PIN (2)

// initialize the library instances
GSM gsmAccess;
GSM_SMS sms;

// Array to hold the number a SMS is retreived from
char senderNumber[20];

char *byteArrayToCharArray(uint8_t *bytes, uint8_t len);
uint8_t *charArrayToByteArray(char *string);
void splitArray(uint8_t src[], uint8_t dest[], uint8_t from, uint8_t to);
void keccak256(const uint8_t *data, uint16_t length, uint8_t *result);
void assignAttribute(int pos, string atr, TX *tx);
TX *receiveTransaction(string transaction);
uint8_t *getPublicKey(uint8_t *privatekey);
uint8_t *getAddress(uint8_t *publickey);
const char *signTransaction(TX tx);

char *byteArrayToCharArray(uint8_t *bytes, uint8_t len)
{

    char *ret = new char[len * 2 + 1];
    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int j = 0; j < len; j++)
    {
        ret[j * 2] = hexval[((bytes[j] >> 4) & 0xF)];
        ret[(j * 2) + 1] = hexval[(bytes[j]) & 0x0F];
    }
    ret[len * 2] = '\0';
    return ret;
}

uint8_t *charArrayToByteArray(char *string)
{

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0)
        return NULL;

    size_t dlength = slength / 2;

    uint8_t *data = new uint8_t[dlength];
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength)
    {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
        {
            delete[] data;
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

void splitArray(uint8_t src[], uint8_t dest[], uint8_t from, uint8_t to)
{
    int i = 0;
    for (int ctr = from; ctr < to; ctr++)
    {
        dest[i] = src[ctr];
        i++;
    }
}
void initScreen()
{
    oled.init();         // Initialze SSD1306 OLED display
    oled.clearDisplay(); // Clear screen
    //    oled.setFont(font5x7); // Set font type (default 8x8)

    oled.setTextXY(0, 0); // Set cursor position, start of line 0
    oled.putString(" Harmony wallet ");
    oled.setTextXY(1, 0); // Set cursor position, start of line 1
    oled.putString("tel:+31622167828");
}

static void waitForButton()
{
    // Wait for the button down
    while (!digitalRead(BUTTON_PIN))
    {
        delay(50);
    }

    // De-bounce
    delay(50);

    // wait for the button up
    while (digitalRead(BUTTON_PIN))
    {
        delay(50);
    }
}

void setup()
{

    Serial.begin(9600);
    while (!Serial)
    {
        ; // wait for serial port to connect. Needed for native USB port only
    }

    Wire.begin();

    initScreen();

    // connection state
    bool connected = false;

    // Start GSM connection
    while (!connected)
    {
        Serial.println("connecting..");
        if (gsmAccess.begin(SECRET_PINNUMBER) == GSM_READY)
        {
            connected = true;
        }
        else
        {
            Serial.println("Not connected");
            delay(1000);
        }
    }
    oled.setTextXY(2, 0);
    Serial.println("Connected!");
    oled.putString("   GSM ready!   ");

    // display public key
    // Serial.println(byteArrayToCharArray(getPublicKey(privatekey), 64));

    // display public address
    // Serial.print("0x");
    // Serial.println(byteArrayToCharArray(getAddress(getPublicKey(privatekey)), 20));

    // Serialized transaction :TX|nonce|gasPrice|gasLimit|to|value|data

    //Serial.println("raw TX:");
    //Serial.println(raw_tx);

    TX *tx = receiveTransaction("TX|0x21|0x04a817c800|0x0493e0|0x115960decb7aa60f8d53c39cc65e30c860a2e171|0x05f5e100|0x");
    const char *raw_tx = signTransaction(*tx);
    sendMessage(raw_tx);
}
void sendMessage(const char *msg)
{
    bool sent = false;
    while (!sent)
    {

        if (!sent)
        {
            char remoteNum[20] = "+31644220976"; // telephone number to send sms
            // char remoteNum[20] = "+32460208830"; // telephone number to send sms
            // sms text
            char txtMsg[200];
            memcpy(txtMsg, msg, strlen(msg));
            Serial.println("SENDING");
            Serial.println();
            Serial.println("Message:");
            Serial.println(txtMsg);

            // send the message
            sms.beginSMS(remoteNum);
            sms.print(txtMsg);
            sms.endSMS();
            Serial.println("\nCOMPLETE!\n");
            sent = true;
        }
    }
}
void handleMessage(char *message)
{
    String s = String(message);
    Serial.println("Twilio says:");
    Serial.println(s);
    resetScreen();
    if (s.startsWith("START"))
    {
        oled.putString("START");
    }

    if (s.startsWith("BALANCE"))
    {
        oled.putString("BALANCE");
    }

    if (s.startsWith("TX|"))
    {
        oled.putString("RECEIVE TRANSACTION");
        // "TX|0x1f|0x04a817c800|0x0493e0|0x115960decb7aa60f8d53c39cc65e30c860a2e171|0x05f5e100|0x"
        // waitForButton();
        TX *tx = receiveTransaction(message);
        const char *raw_tx = signTransaction(*tx);
    }

    delete message;
}

void resetScreen()
{
    oled.init();
    oled.setTextXY(1, 0);
}

char compareCharacters(char a, char b)
{
    if (a == b)
        return 0;
    else
        return -1;
}

void loop()
{
    char c;

    // If there are any SMSs available()
    if (sms.available())
    {
        Serial.println("Message received from:");
        sms.remoteNumber(senderNumber, 20);
        Serial.println(senderNumber);
        // Get remote number
        // sms.remoteNumber(senderNumber, 20);
        // oled.putString(senderNumber);

        // An example of message disposal
        // Any messages starting with # should be discarded
        if (sms.peek() == '#')
        {
            // Serial.println("Discarded SMS");
            sms.flush();
        }

        // Read message bytes and print them
        oled.init();
        oled.setTextXY(1, 0); // Set cursor position, start of line 1
        char smsData[127];
        byte smsIndex = 0;
        while (c = sms.read())
        {
            // message sanity check
            if ((isalnum(c) == 0 && c != '|' && c != ' ') || smsIndex > 127)
                break;

            smsData[smsIndex++] = c;
            smsData[smsIndex] = '\0'; // Keep string NULL terminated
        }
        Serial.println("message:");
        Serial.println(smsData);
        handleMessage(smsData);

        // Serial.println("\nEND OF MESSAGE");

        // Delete message from modem memory
        sms.flush();
        // Serial.println("MESSAGE DELETED");
    }
}

const char *signTransaction(TX tx)
{
    RLP rlp;
    string enc = rlp.encode(tx, true);

    uint8_t *hashval = new uint8_t[HASH_LENGTH];
    keccak256((uint8_t *)(enc.c_str()), enc.size(), hashval);
    // Serial.println(byteArrayToCharArray(hashval, HASH_LENGTH));
    // printf("Hash: %s\n\n", byteArrayToCharArray(hashval, HASH_LENGTH));

    uint8_t *sig = new uint8_t[SIGNATURE_LENGTH];
    ethers_sign_hash(privatekey, hashval, sig);

    uint8_t *r = new uint8_t[32];
    uint8_t *s = new uint8_t[32];
    // Serial.println(byteArrayToCharArray(sig, 64));
    splitArray(sig, r, 0, 32);
    splitArray(sig, s, 32, 64);

    tx.r = string("0x") + byteArrayToCharArray(r, 32);
    tx.s = string("0x") + byteArrayToCharArray(s, 32);

    // Serial.println("R signature u:");
    Serial.println(tx.r.c_str());
    // Serial.println("C signature u:");
    Serial.println(tx.s.c_str());

    tx.v = "0x1b";
    string encoded_1b = string("0x") + rlp.bytesToHex(rlp.encode(tx, false));
    Serial.println(encoded_1b.c_str());
    tx.v = "0x1c";
    string encoded_1c = string("0x") + rlp.bytesToHex(rlp.encode(tx, false));
    Serial.println(encoded_1c.c_str());

    delete r;
    delete s;
    delete sig;
    delete hashval;

    return encoded_1b.c_str();
}

//SHA-3
void keccak256(const uint8_t *data, uint16_t length, uint8_t *result)
{

    SHA3_CTX context;
    keccak_init(&context);
    keccak_update(&context, (const unsigned char *)data, (size_t)length);
    keccak_final(&context, (unsigned char *)result);

    memset((char *)&context, 0, sizeof(SHA3_CTX));
}

uint8_t *getPublicKey(uint8_t *privatekey)
{
    uint8_t *publickey = new uint8_t[64];
    compute_public_key(privatekey, publickey);

    return publickey;
}

uint8_t *getAddress(uint8_t *publickey)
{

    uint8_t *address = new uint8_t[20];
    uint8_t *pubhash = new uint8_t[64];
    keccak256(publickey, 64, pubhash);
    memcpy(address, &pubhash[12], 20);
    return address;
}

TX *receiveTransaction(string s)
{
    string delimiter = "|";

    TX *tx = new TX();

    size_t pos = 0;
    string token;
    int i = 0;
    while ((pos = s.find(delimiter)) != string::npos)
    {
        token = s.substr(0, pos);
        assignAttribute(i, token, tx);
        s.erase(0, pos + delimiter.length());
        i++;
    }
    assignAttribute(i, s, tx);

    return tx;
}

void assignAttribute(int pos, string atr, TX *tx)
{
    switch (pos)
    {
    case 1:
        tx->nonce = atr;
        break;
    case 2:
        tx->gasPrice = atr;
        break;
    case 3:
        tx->gasLimit = atr;
        break;
    case 4:
        tx->to = atr;
        break;
    case 5:
        tx->value = atr;
        break;
    case 6:
        tx->data = atr;
        break;
    }
}
