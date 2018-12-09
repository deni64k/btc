#pragma once

#include <cstdint>

#include "utility.hxx"

namespace btc::proto {

struct opcode_t {
  enum state {
    ok,
    abort,
    abort_if_executed,
    ignore
  };

  std::uint8_t opcode;
  char const*  name;
  int push;
  int output;
  state enabled = ok;
};

#define CONCAT_I(x, y) x ## y
#define CONCAT(x, y) CONCAT_I(x, y)
#define STRINGIZE_I(x) #x
#define STRINGIZE(x) STRINGIZE_I(x)

#define EXPAND(...)  EXPAND0(EXPAND0(EXPAND0(EXPAND0(__VA_ARGS__))))
#define EXPAND0(...) EXPAND1(EXPAND1(EXPAND1(EXPAND1(__VA_ARGS__))))
#define EXPAND1(...) EXPAND2(EXPAND2(EXPAND2(EXPAND2(__VA_ARGS__))))
#define EXPAND2(...) EXPAND3(EXPAND3(EXPAND3(EXPAND3(__VA_ARGS__))))
#define EXPAND3(...) __VA_ARGS__

#define EMPTY()
#define DEFER(m) m EMPTY() ()

#define FOR_EACH_PASSIVE() FOR_EACH_I
#define FOR_EACH(m, ...)   EXPAND(FOR_EACH_I(m, __VA_ARGS__))
#define FOR_EACH_I(m, ...) CONCAT(FOR_EACH_BOOM_, __VA_OPT__(1))(m, __VA_ARGS__)
#define FOR_EACH_BOOM_1(m, arg, ...)            \
  m(arg)                                        \
  DEFER(FOR_EACH_PASSIVE)(m, __VA_ARGS__)
#define FOR_EACH_BOOM_(m, ...)

#define DECLARE_ENUM_OP(M_elem)                                         \
  BOOST_PP_TUPLE_ELEM(5, 0, M_elem) = BOOST_PP_TUPLE_ELEM(5, 1, M_elem),
    
#define DECLARE_ENUM(...)                                               \
  enum {                                                                \
    FOR_EACH(DECLARE_ENUM_OP, __VA_ARGS__)                              \
  };

#define DECLARE_OPCODES_OP(M_elem)                                  \
  {                                                                 \
    BOOST_PP_TUPLE_ELEM(5, 1, M_elem),                              \
    BOOST_PP_STRINGIZE(BOOST_PP_TUPLE_ELEM(4, 0, M_elem)),          \
    BOOST_PP_TUPLE_ELEM(5, 2, M_elem),                              \
    BOOST_PP_TUPLE_ELEM(5, 3, M_elem),                              \
    opcode_t:: BOOST_PP_TUPLE_ELEM(5, 4, M_elem),                   \
  },

#define DECLARE_OPCODES(...)                                            \
  static opcode_t opcodes[] = {                                         \
    FOR_EACH(DECLARE_OPCODES_OP, __VA_ARGS__)                           \
  };

#define OPCODES(...)                                            \
  DECLARE_ENUM(__VA_ARGS__)                                     \
  DECLARE_OPCODES(__VA_ARGS__)

OPCODES(
    //
    // * Constants
    //
    // An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)
    // Input:  Nothing
    // Output: (empty value)
    (OP_0     , 0, 0, 0, ok),
    (OP_FALSE , 0, 0, 0, ok),

    // The next opcode bytes is data to be pushed onto the stack
    // Input:  (special)
    // Output: data
    // N/A 1-75	0x01-0x4b
    (DATA_1  , 1 , 1 , 0, ok),
    (DATA_2  , 2 , 2 , 0, ok),
    (DATA_3  , 3 , 3 , 0, ok),
    (DATA_4  , 4 , 4 , 0, ok),
    (DATA_5  , 5 , 5 , 0, ok),
    (DATA_6  , 6 , 6 , 0, ok),
    (DATA_7  , 7 , 7 , 0, ok),
    (DATA_8  , 8 , 8 , 0, ok),
    (DATA_9  , 9 , 9 , 0, ok),
    (DATA_10 , 10, 10, 0, ok),
    (DATA_11 , 11, 11, 0, ok),
    (DATA_12 , 12, 12, 0, ok),
    (DATA_13 , 13, 13, 0, ok),
    (DATA_14 , 14, 14, 0, ok),
    (DATA_15 , 15, 15, 0, ok),
    (DATA_16 , 16, 16, 0, ok),
    (DATA_17 , 17, 17, 0, ok),
    (DATA_18 , 18, 18, 0, ok),
    (DATA_19 , 19, 19, 0, ok),
    (DATA_20 , 20, 20, 0, ok),
    (DATA_21 , 21, 21, 0, ok),
    (DATA_22 , 22, 22, 0, ok),
    (DATA_23 , 23, 23, 0, ok),
    (DATA_24 , 24, 24, 0, ok),
    (DATA_25 , 25, 25, 0, ok),
    (DATA_26 , 26, 26, 0, ok),
    (DATA_27 , 27, 27, 0, ok),
    (DATA_28 , 28, 28, 0, ok),
    (DATA_29 , 29, 29, 0, ok),
    (DATA_30 , 30, 30, 0, ok),
    (DATA_31 , 31, 31, 0, ok),
    (DATA_32 , 32, 32, 0, ok),
    (DATA_33 , 33, 33, 0, ok),
    (DATA_34 , 34, 34, 0, ok),
    (DATA_35 , 35, 35, 0, ok),
    (DATA_36 , 36, 36, 0, ok),
    (DATA_37 , 37, 37, 0, ok),
    (DATA_38 , 38, 38, 0, ok),
    (DATA_39 , 39, 39, 0, ok),
    (DATA_40 , 40, 40, 0, ok),
    (DATA_41 , 41, 41, 0, ok),
    (DATA_42 , 42, 42, 0, ok),
    (DATA_43 , 43, 43, 0, ok),
    (DATA_44 , 44, 44, 0, ok),
    (DATA_45 , 45, 45, 0, ok),
    (DATA_46 , 46, 46, 0, ok),
    (DATA_47 , 47, 47, 0, ok),
    (DATA_48 , 48, 48, 0, ok),
    (DATA_49 , 49, 49, 0, ok),
    (DATA_50 , 50, 50, 0, ok),
    (DATA_51 , 51, 51, 0, ok),
    (DATA_52 , 52, 52, 0, ok),
    (DATA_53 , 53, 53, 0, ok),
    (DATA_54 , 54, 54, 0, ok),
    (DATA_55 , 55, 55, 0, ok),
    (DATA_56 , 56, 56, 0, ok),
    (DATA_57 , 57, 57, 0, ok),
    (DATA_58 , 58, 58, 0, ok),
    (DATA_59 , 59, 59, 0, ok),
    (DATA_60 , 60, 60, 0, ok),
    (DATA_61 , 61, 61, 0, ok),
    (DATA_62 , 62, 62, 0, ok),
    (DATA_63 , 63, 63, 0, ok),
    (DATA_64 , 64, 64, 0, ok),
    (DATA_65 , 65, 65, 0, ok),
    (DATA_66 , 66, 66, 0, ok),
    (DATA_67 , 67, 67, 0, ok),
    (DATA_68 , 68, 68, 0, ok),
    (DATA_69 , 69, 69, 0, ok),
    (DATA_70 , 70, 70, 0, ok),
    (DATA_71 , 71, 71, 0, ok),
    (DATA_72 , 72, 72, 0, ok),
    (DATA_73 , 73, 73, 0, ok),
    (DATA_74 , 74, 74, 0, ok),
    (DATA_75 , 75, 75, 0, ok),

    // The next byte contains the number of bytes to be pushed onto the stack.
    // Input:  (special)
    // Output: data
    (OP_PUSHDATA1 , 76, 1, 0, ok),  // 0x4c

    // The next two bytes contain the number of bytes to be pushed onto the stack in little endian order.
    // Input:  (special)
    // Output: data
    (OP_PUSHDATA2 , 77, 2, 0, ok),  // 0x4d

    // The next four bytes contain the number of bytes to be pushed onto the stack in little endian order.
    // Input:  (special)
    // Output: data
    (OP_PUSHDATA4 , 78, 4, 0, ok),  // 0x4e

    // The number -1 is pushed onto the stack.
    // Input:  Nothing
    // Output: -1
    (OP_1NEGATE   , 79, 0, 1, ok),  // 0x4f

    // The number 1 is pushed onto the stack.
    // Input:  Nothing
    // Output: 1
    (OP_1         , 81, 0, 1, ok),  // 0x51
    (OP_TRUE      , 81, 0, 1, ok),

    // The number in the word name (2-16) is pushed onto the stack.
    // Input: Nothing
    // Output: 2-16
    (OP_2  , 82, 0, 1, ok),  // 0x52
    (OP_3  , 83, 0, 1, ok),
    (OP_4  , 84, 0, 1, ok),
    (OP_5  , 85, 0, 1, ok),
    (OP_6  , 86, 0, 1, ok),
    (OP_7  , 87, 0, 1, ok),
    (OP_8  , 88, 0, 1, ok),
    (OP_9  , 89, 0, 1, ok),
    (OP_10 , 90, 0, 1, ok),
    (OP_11 , 91, 0, 1, ok),
    (OP_12 , 92, 0, 1, ok),
    (OP_13 , 93, 0, 1, ok),
    (OP_14 , 94, 0, 1, ok),
    (OP_15 , 95, 0, 1, ok),
    (OP_16 , 96, 0, 1, ok),  // 0x60

    //
    // * Flow control
    //
    // Does nothing.
    // Input:  Nothing
    // Output: Nothing
    (OP_NOP , 97, 0, 0, ok),

    // If the top stack value is not False, the statements are executed. The top stack value is removed.
    // <expression> if [statements] [else [statements]]* endif
    (OP_IF  , 99, 0, 0, ok),

    // If the top stack value is False, the statements are executed. The top stack value is removed.
    // <expression> notif [statements] [else [statements]]* endif
    (OP_NOTIF , 100, 0, 0, ok),

    // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and
    // if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
    // <expression> if [statements] [else [statements]]* endif
    (OP_ELSE , 103, 0, 0, ok),

    // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without
    // OP_IF earlier is also invalid.
    // <expression> if [statements] [else [statements]]* endif
    (OP_ENDIF , 104, 0, 0, ok),

    // Marks transaction as invalid if top stack value is not true. The top stack value is removed.
    // Input:  True / false
    // Output: Nothing / fail
    (OP_VERIFY , 105, 0, 0, ok),

    // Marks transaction as invalid. A standard way of attaching extra data to transactions is
    // to add a zero-value output with a scriptPubKey consisting of OP_RETURN followed by exactly
    // one pushdata op. Such outputs are provably unspendable, reducing their cost to the network.
    // Currently it is usually considered non-standard (though valid) for a transaction to have more
    // than one OP_RETURN output or an OP_RETURN output with more than one pushdata op.
    // Input:  Nothing
    // Output: fail
    (OP_RETURN , 106, 0, 0, ok),

    //
    // * Stack
    //
    // Puts the input onto the top of the alt stack. Removes it from the main stack.
    // Input:  x1
    // Output: (alt)x1
    (OP_TOALTSTACK , 107, 0, 1, ok),

    // Puts the input onto the top of the main stack. Removes it from the alt stack.
    // Input:  (alt)x1
    // Output: x1
    (OP_FROMALTSTACK , 108, 0, 1, ok),

    // If the top stack value is not 0, duplicate it.
    // Input:  x
    // Output: x / x x
    (OP_IFDUP , 115, 0, 2, ok),

    // Puts the number of stack items onto the stack.
    // Input:  Nothing
    // Output: <Stack size>
    (OP_DEPTH , 116, 0, 1, ok),

    // Removes the top stack item
    // Input:  x
    // Output: Nothing
    (OP_DROP , 117, 0, 0, ok),

    // Duplicates the top stack item.
    // Input:  x
    // Output: x x
    (OP_DUP , 118, 0, 2, ok),

    // Removes the second-to-top stack item.
    // Input:  x1 x2
    // Output: x2
    (OP_NIP , 119, 0, 1, ok),

    // Copies the second-to-top stack item to the top.
    // Input:  x1 x2
    // Output: x1 x2 x1
    (OP_OVER , 120, 0, 3, ok),

    // The item n back in the stack is copied to the top.
    // Input:  xn ... x2 x1 x0 <n>
    // Output: xn ... x2 x1 x0 xn
    (OP_PICK , 121, 0, 2, ok),

    // The item n back in the stack is moved to the top.
    // Input:  xn ... x2 x1 x0 <n>
    // Output: ... x2 x1 x0 xn
    (OP_ROLL , 122, 0, 1, ok),

    // The top three items on the stack are rotated to the left.
    // Input:  x1 x2 x3
    // Output: x2 x3 x1
    (OP_ROT , 123, 0, 3, ok),
  
    // The top two items on the stack are swapped.
    // Input:  x1 x2
    // Output: x2 x1
    (OP_SWAP , 124, 0, 2, ok),

    // The item at the top of the stack is copied and inserted before the second-to-top item.
    // Input:  x1 x2
    // Output: x2 x1 x2
    (OP_TUCK , 125, 0, 0, ok),

    // Removes the top two stack items.
    // Input:  x1 x2
    // Output: Nothing
    (OP_2DROP , 109, 0, 0, ok),

    // Duplicates the top two stack items.
    // Input:  x1 x2
    // Output: x1 x2 x1 x2
    (OP_2DUP , 110, 0, 0, ok),

    // Duplicates the top three stack items.
    // Input:  x1 x2 x3
    // Output: x1 x2 x3 x1 x2 x3
    (OP_3DUP , 111, 0, 0, ok),

    // Copies the pair of items two spaces back in the stack to the front.
    // Input:  x1 x2 x3 x4
    // Output: x1 x2 x3 x4 x1 x2
    (OP_2OVER , 112, 0, 0, ok),

    // The fifth and sixth items back are moved to the top of the stack.
    // Input:  x1 x2 x3 x4 x5 x6
    // Output: x3 x4 x5 x6 x1 x2
    (OP_2ROT , 113, 0, 0, ok),

    // Swaps the top two pairs of items.
    // Input:  x1 x2 x3 x4
    // Output: x3 x4 x1 x2
    (OP_2SWAP , 114, 0, 0, ok),

    //
    // * Splice
    //
    // [DISABLED]
    // Concatenates two strings.
    // Input:  x1 x2
    // Output: out
    (OP_CAT , 126, 0, 0, abort),

    // [DISABLED]
    // Returns a section of a string.
    // Input:  in begin size
    // Output: out
    (OP_SUBSTR , 127, 0, 0, abort),

    // [DISABLED]
    // Keeps only characters left of the specified point in a string.
    // Input:  in size
    // Output: out
    (OP_LEFT , 128, 0, 0, abort),

    // [DISABLED]
    // Keeps only characters right of the specified point in a string.
    // Input:  in size
    // Output: out
    (OP_RIGHT , 129, 0, 0, abort),

    // Pushes the string length of the top element of the stack (without popping it).
    // Input:  in
    // Output: in size
    (OP_SIZE , 130, 0, 0, ok),

    //
    // * Bitwise logic
    //
    // [DISABLED]
    // Flips all of the bits in the input.
    // Input:  in
    // Output: out
    (OP_INVERT      , 131, 0, 0, abort),
    // [DISABLED]
    // Boolean and between each bit in the inputs.
    // Input:  x1 x2
    // Output: out
    (OP_AND         , 132, 0, 0, abort),
    // [DISABLED]
    // Boolean or between each bit in the inputs.
    // Input:  x1 x2
    // Output: out
    (OP_OR          , 133, 0, 0, abort),
    // [DISABLED]
    // Boolean exclusive or between each bit in the inputs.
    // Input:  x1 x2
    // Output: out
    (OP_XOR         , 134, 0, 0, abort),
    // Returns 1 if the inputs are exactly equal, 0 otherwise.
    // Input:  x1 / x2
    // Output: True / false
    (OP_EQUAL       , 135, 0, 0, ok),
    // Same as OP_EQUAL, but runs OP_VERIFY afterward.
    // Input:  x1 / x2
    // Output: Nothing / fail
    (OP_EQUALVERIFY , 136, 0, 0, ok),

    //
    // * Arithmetic
    //
    // 1 is added to the input.
    // Input:  in
    // Output: out
    (OP_1ADD , 139, 0, 0, ok),
    // 1 is subtracted from the input.
    // Input:  in
    // Output: out
    (OP_1SUB , 140, 0, 0, ok),
    // [DISABLED]
    // The input is multiplied by 2. disabled.
    // Input:  in
    // Output: out
    (OP_2MUL , 141, 0, 0, abort),
    // [DISABLED]
    // The input is divided by 2. disabled.
    // Input:  in
    // Output: out
    (OP_2DIV , 142, 0, 0, abort),
    // The sign of the input is flipped.
    // Input:  in
    // Output: out
    (OP_NEGATE , 143, 0, 0, ok),
    // The input is made positive.
    // Input:  in
    // Output: out
    (OP_ABS , 144, 0, 0, ok),
    // If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    // Input:  in
    // Output: out
    (OP_NOT , 145, 0, 0, ok),
    // Returns 0 if the input is 0. 1 otherwise.
    // Input:  in
    // Output: out
    (OP_0NOTEQUAL , 146, 0, 0, ok),
    // a is added to b.
    // Input:  a b
    // Output: out
    (OP_ADD , 147, 0, 0, ok),
    // b is subtracted from a.
    // Input:  a b
    // Output: out
    (OP_SUB , 148, 0, 0, ok),
    // [DISABLED]
    // a is multiplied by b.
    // Input:  a b
    // Output: out
    (OP_MUL , 149, 0, 0, abort),
    // [DISABLED]
    // a is divided by b.
    // Input:  a b
    // Output: out
    (OP_DIV , 150, 0, 0, abort),
    // [DISABLED]
    // Returns the remainder after dividing a by b.
    // Input:  a b
    // Output: out
    (OP_MOD , 151, 0, 0, abort),
    // [DISABLED]
    // Shifts a left b bits, preserving sign.
    // Input:  a b
    // Output: out
    (OP_LSHIFT , 152, 0, 0, abort),
    // [DISABLED]
    // Shifts a right b bits, preserving sign.
    // Input:  a b
    // Output: out
    (OP_RSHIFT , 153, 0, 0, abort),
    // If both a and b are not "" (null string), the output is 1. Otherwise 0.
    // Input:  a b
    // Output: out
    (OP_BOOLAND , 154, 0, 0, ok),
    // If a or b is not "" (null string), the output is 1. Otherwise 0.
    // Input:  a b
    // Output: out
    (OP_BOOLOR , 155, 0, 0, ok),
    // Returns 1 if the numbers are equal, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_NUMEQUAL , 156, 0, 0, ok),
    // Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    // Input:  a b
    // Output: Nothing / fail
    (OP_NUMEQUALVERIFY , 157, 0, 0, ok),
    // Returns 1 if the numbers are not equal, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_NUMNOTEQUAL , 158, 0, 0, ok),
    // Returns 1 if a is less than b, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_LESSTHAN , 159, 0, 0, ok),
    // Returns 1 if a is greater than b, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_GREATERTHAN , 160, 0, 0, ok),
    // Returns 1 if a is less than or equal to b, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_LESSTHANOREQUAL , 161, 0, 0, ok),
    // Returns 1 if a is greater than or equal to b, 0 otherwise.
    // Input:  a b
    // Output: out
    (OP_GREATERTHANOREQUAL , 162, 0, 0, ok),
    // Returns the smaller of a and b.
    // Input:  a b
    // Output: out
    (OP_MIN , 163, 0, 0, ok),
    // Returns the larger of a and b.
    // Input:  a b
    // Output: out
    (OP_MAX , 164, 0, 0, ok),
    // Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    // Input:  x min max
    // Output: out
    (OP_WITHIN , 165, 0, 0, ok),

    //
    // * Crypto
    //
    // The input is hashed using RIPEMD-160.
    // Input:  in
    // Output: hash
    (OP_RIPEMD160 , 166, 0, 0, ok),
    // The input is hashed using SHA-1.
    // Input:  in
    // Output: hash
    (OP_SHA1 , 167, 0, 0, ok),
    // The input is hashed using SHA-256.
    // Input:  in
    // Output: hash
    (OP_SHA256 , 168, 0, 0, ok),
    // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    // Input:  in
    // Output: hash
    (OP_HASH160 , 169, 0, 0, ok),
    // The input is hashed two times with SHA-256.
    // Input:  in
    // Output: hash
    (OP_HASH256 , 170, 0, 0, ok),
    // All of the signature checking words will only match signatures to the data after the most
    // recently-executed OP_CODESEPARATOR.
    // Input:  Nothing
    // Output: Nothing
    (OP_CODESEPARATOR , 171, 0, 0, ok),
    // The entire transaction's outputs, inputs, and script (from the most recently-executed
    // OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid
    // signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
    // Input:  sig pubkey
    // Output: True / false
    (OP_CHECKSIG , 172, 0, 0, ok),
    // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
    // Input:  sig pubkey
    // Output: Nothing / fail
    (OP_CHECKSIGVERIFY , 173, 0, 0, ok),
    // Compares the first signature against each public key until it finds an ECDSA match. Starting
    // with the subsequent public key, it compares the second signature against each remaining public
    // key until it finds an ECDSA match. The process is repeated until all signatures have been
    // checked or not enough public keys remain to produce a successful result. All signatures need to
    // match a public key. Because public keys are not checked again if they fail any signature
    // comparison, signatures must be placed in the scriptSig using the same order as their
    // corresponding public keys were placed in the scriptPubKey or redeemScript. If all signatures
    // are valid, 1 is returned, 0 otherwise. Due to a bug, one extra unused value is removed from the
    // stack.
    // Input:  x sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>
    // Output: True / False
    (OP_CHECKMULTISIG , 174, 0, 0, ok),
    // Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
    // Input:  x sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>
    // Output: Nothing / fail
    (OP_CHECKMULTISIGVERIFY , 175, 0, 0, ok),

    //
    // * Locktime
    //
    // Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime
    // field, otherwise script evaluation continues as though an OP_NOP was executed. Transaction is
    // also invalid if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top
    // stack item is greater than or equal to 500000000 while the transaction's nLockTime field is
    // less than 500000000, or vice versa; or 4. the input's nSequence field is equal to
    // 0xffffffff. The precise semantics are described in BIP0065.
    // (previously OP_NOP2)
    // Input:  x
    // Output: x / fail
    (OP_CHECKLOCKTIMEVERIFY , 177, 0, 0, ok),

    // Marks transaction as invalid if the relative lock time of the input (enforced by BIP0068 with
    // nSequence) is not equal to or longer than the value of the top stack item. The precise
    // semantics are described in BIP0112.
    // (previously OP_NOP3)
    // Input:  x
    // Output: x / fail
    (OP_CHECKSEQUENCEVERIFY , 178, 0, 0, ok),
  
    //
    // * Pseudo-words
    //
    // Represents a public key hashed with OP_HASH160.
    (OP_PUBKEYHASH    , 253, 0, 0, ok),
    // Represents a public key compatible with OP_CHECKSIG.
    (OP_PUBKEY        , 254, 0, 0, ok),
    // Matches any opcode that is not yet assigned.
    (OP_INVALIDOPCODE , 255, 0, 0, ok),

    //
    // * Reserved words
    //
    // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    (OP_RESERVED  , 80, 0, 0, abort_if_executed),
    // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    (OP_VER       , 98, 0, 0, abort_if_executed),
    // Transaction is invalid even when occuring in an unexecuted OP_IF branch
    (OP_VERIF     , 101, 0, 0, abort),
    // Transaction is invalid even when occuring in an unexecuted OP_IF branch
    (OP_VERNOTIF  , 102, 0, 0, abort),
    // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    (OP_RESERVED1 , 137, 0, 0, abort_if_executed),
    // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    (OP_RESERVED2 , 138, 0, 0, abort_if_executed),
    // The word is ignored. Does not mark transaction as invalid.
    (OP_NOP1  , 176, 0, 0, ignore),
    (OP_NOP4  , 179, 0, 0, ignore),
    (OP_NOP5  , 180, 0, 0, ignore),
    (OP_NOP6  , 181, 0, 0, ignore),
    (OP_NOP7  , 182, 0, 0, ignore),
    (OP_NOP8  , 183, 0, 0, ignore),
    (OP_NOP9  , 184, 0, 0, ignore),
    (OP_NOP10 , 185, 0, 0, ignore)
)

struct script {
  std::vector<std::uint8_t> code;
};

inline opcode_t const& find_opcode(std::uint8_t opcode) {
  for (auto& x : opcodes) {
    if (x.opcode == opcode) {
      return x;
    }
  }
  return opcodes[0];
}

inline std::ostream& operator << (std::ostream& os, script const& s) {
  os << std::hex;
  for (unsigned i = 0; i < s.code.size(); ++i) {
    unsigned stride = 0;
    auto const& op = find_opcode(s.code[i]);
    os << op.name;
    if (op.opcode == OP_PUSHDATA1) {
      stride = s.code[++i];
      os << '(' << std::dec << stride << std::hex << ')';
    } else if (op.opcode == OP_PUSHDATA2) {
      stride = reinterpret_cast<std::uint16_t const&>(s.code[++i]);
      i += 1;
      os << '(' << std::dec << stride << std::hex << ')';
    } else if (op.opcode == OP_PUSHDATA4) {
      stride = reinterpret_cast<std::uint32_t const&>(s.code[++i]);
      i += 3;
      os << '(' << std::dec << stride << std::hex << ')';
    } else if (op.push > 0) {
      stride = op.push;
    }

    if (stride) {
      os << '<';
      for (unsigned j = i+1; j < i+1+op.push && j < s.code.size(); ++j) {
        os << std::setw(2) << std::setfill('0') << unsigned{s.code[j]};
      }
      os << '>';
    }
    os << ' ';
    i += stride;
  }
  os << std::resetiosflags(std::ios_base::basefield);
  return os;
}

}
