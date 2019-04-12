
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
#include "../libs/crypto/ecdsa.h"
#include "../libs/crypto/bignum256.h"
}
#include <keccak256.h>
#include <ethers.h>
#include "../libs/rlp/TX.h"
#include "../libs/rlp/RLP.h"
#include "keccak256.h"

using namespace std;

#define HASH_LENGTH 32
#define SIGNATURE_LENGTH 64