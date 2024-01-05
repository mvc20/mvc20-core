import UniqueProto = require('./uniqueProto');
import ProtoHeader = require('./protoheader');
import Common = require('./common');
import { mvc } from "mvc-scrypt"

export interface Mvc20Info {
    maxTokenAmount: bigint
    maxMintAmount: bigint
    mintedAmount: bigint
}

// opreturn: <maxTokenAmount(8 bytes)> + <maxMintAmount(8 bytes)> + <mintedAmount(8 bytes)> +  + <contractHashRoot<20 bytes>>

const OP_PUSH_DATA_LEN = 2

const CONTRACT_HASH_ROOT_OFFSET = UniqueProto.FIX_HEADER_LEN + ProtoHeader.HASH_LEN;
const MINTED_AMOUNT_OFFSET = CONTRACT_HASH_ROOT_OFFSET + ProtoHeader.AMOUNT_LEN;
const MAX_MINT_AMOUNT_OFFSET = MINTED_AMOUNT_OFFSET + ProtoHeader.AMOUNT_LEN;
const MAX_TOKEN_AMOUNT_OFFSET = MAX_MINT_AMOUNT_OFFSET + ProtoHeader.AMOUNT_LEN;

const DATA_OFFSET = MAX_TOKEN_AMOUNT_OFFSET

export const CUSTOM_DATA_LEN = DATA_OFFSET - UniqueProto.FIX_HEADER_LEN

export const OP_MINT = 0

export const getDataLen = function() {
    return DATA_OFFSET
}

export function getMaxTokenAmount(script: Buffer) {
    return script.readBigUInt64LE(script.length - MAX_TOKEN_AMOUNT_OFFSET)
}

export function getMaxMintAmount(script: Buffer) {
    return script.readBigUInt64LE(script.length - MAX_MINT_AMOUNT_OFFSET)
}

export function getMintedAmount(script: Buffer) {
    return script.readBigUInt64LE(script.length - MINTED_AMOUNT_OFFSET)
}

export function getMvc20Info(script: Buffer) {
    return {
        maxTokenAmount: getMaxTokenAmount(script),
        maxMintAmount: getMaxMintAmount(script),
        mintedAmount: getMintedAmount(script)
    }
}

export function getNewScript(script: Buffer, mintedAmount: bigint) {
    return Buffer.concat([
        script.subarray(0, script.length - MINTED_AMOUNT_OFFSET),
        Common.getUInt64Buf(mintedAmount),
        script.subarray(script.length - MINTED_AMOUNT_OFFSET + ProtoHeader.AMOUNT_LEN)
    ])
}

export function getContractCode(scriptBuf: Buffer) {
  const dataLen = getDataLen()
  return scriptBuf.subarray(0, scriptBuf.length - dataLen - OP_PUSH_DATA_LEN)
}

export function getContractCodeHash(scriptBuf: Buffer) {
  return mvc.crypto.Hash.sha256ripemd160(getContractCode(scriptBuf))
}