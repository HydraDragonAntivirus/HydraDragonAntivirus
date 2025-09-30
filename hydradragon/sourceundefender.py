#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import os
import time
from base64 import b85decode
from base64 import a85decode
from hydra_logger import logger

import hashlib
import zlib
from tgcrypto import ctr256_decrypt
import msgpack
import struct
from importlib.util import MAGIC_NUMBER


def is_sourcedefender_file(file_path: str | Path) -> bool:
    """
    Check if a file is a SourceDefender protected file.
    
    Args:
        file_path (str | Path): Path to the file to check
        
    Returns:
        bool: True if file appears to be SourceDefender protected, False otherwise
    """
    try:
        if not os.path.exists(file_path):
            logger.warning(f"File does not exist: {file_path}")
            return False
            
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext != '.pye':
            logger.debug(f"File extension '{file_ext}' is not .pye")
            return False
            
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        if len(lines) < 3:
            logger.debug("File has insufficient lines for SourceDefender format")
            return False
            
        # Check if first line looks like base85 encoded data
        first_line = lines[1].strip()
        if len(first_line) < 10:
            return False
            
        # Try to decode first line (should be IV)
        try:
            b85decode(first_line)
            logger.debug("File appears to be SourceDefender protected")
            return True
        except:
            try:
                a85decode(first_line)
                logger.debug("File appears to be SourceDefender protected (a85 format)")
                return True
            except:
                logger.debug("File does not appear to be SourceDefender protected")
                return False
                
    except Exception as e:
        logger.error(f"Error checking if file is SourceDefender protected: {str(e)}")
        return False


class Unprotect:
    def __init__(self, pye_file: str | Path, key_hex: str, iv_hex: str, ciphertext_hex: str):
        self.key = bytes.fromhex(key_hex)
        self.iv = bytes.fromhex(iv_hex)
        self.ciphertext = bytes.fromhex(ciphertext_hex.replace("\n", "").replace(" ", ""))
        self.state = b"\x00"
        self.out_file = pye_file
        logger.info(f"Initializing SourceDefender unprotection for file: {pye_file}")
        logger.debug(f"Key length: {len(self.key)} bytes, IV length: {len(self.iv)} bytes")

    def verify_and_unmarshal(self, code_object_data: any):
        # Optional: verify it's a code object
        # import marshal
        # code_obj = marshal.loads(code_object_data)
        
        # print(f"[ + ] Successfully loaded code object: {code_obj}")
        logger.info("Starting code object verification and unmarshaling process")
        
        magic = MAGIC_NUMBER  
        flags = b'\x00\x00\x00\x00'
        timestamp = struct.pack('<I', int(time.time()))
        source_size = struct.pack('<I', 0)
        
        header = magic + flags + timestamp + source_size

        try:
            with open(self.out_file + ".pyc", "wb+") as f:
                f.write(header + code_object_data)
                
            logger.info(f"Successfully exported pyc file: {self.out_file + '.pyc'}")
            return self.out_file + ".pyc"
        except Exception as e:
            logger.error(f"Failed to export pyc file: {str(e)}")
            raise

    # Main function
    def unprotect(self):
        logger.info("Starting SourceDefender unprotection process")
        result = {
            'success': False,
            'version': None,
            'output_file': None,
            'file_type': None,
            'error': None
        }
        
        try:
            plaintext = ctr256_decrypt(self.ciphertext, self.key, self.iv, self.state)
            logger.debug("Successfully decrypted ciphertext")

            msg = msgpack.unpackb(plaintext)
            logger.debug("Successfully unpacked msgpack data")
            
            data = msg.get(b'original_code') or msg.get('original_code') or msg.get('code') or msg.get(b'code') # STRING IF IT WAS OBFUCATED WITH FREE VERSION OF SOURCEDEFENDER CODE OBJECT IF PAID
            if isinstance(data, str):
                # FREE VERSION OF SOURCEDEFENDER
                logger.info("Detected FREE version of SourceDefender")
                result['version'] = 'FREE'
                result['file_type'] = 'source'
                
                output_file = str(self.out_file) + ".py"
                try:
                    with open(output_file, "w+", encoding='utf-8') as writer:
                        writer.write(data)
                        writer.close()
                    
                    result['output_file'] = output_file
                    result['success'] = True
                    logger.info(f"Successfully wrote source code to: {output_file}")
                except Exception as e:
                    result['error'] = f"Failed to write source code file: {str(e)}"
                    logger.error(result['error'])
                    raise
                    
            else:
                logger.info("Detected PAID version of SourceDefender")
                result['version'] = 'PAID'
                result['file_type'] = 'bytecode'
                
                # PAID VERSION OF SOURCEDEFENDER
                output_file = self.verify_and_unmarshal(data)
                result['output_file'] = output_file
                result['success'] = True
                
            return result
                
        except Exception as e:
            result['error'] = f"Unprotection process failed: {str(e)}"
            logger.error(result['error'])
            return result

class PYE_Processor:
    def __init__(self, pye_file: str | Path):
        logger.info(f"Initializing PYE processor for file: {pye_file}")
        self.pye_file = pye_file
        try:
            self.fs = open(pye_file, "r+")
            self.lines = self.fs.readlines()
            logger.debug(f"Successfully read {len(self.lines)} lines from PYE file")
        except Exception as e:
            logger.error(f"Failed to initialize PYE processor: {str(e)}")
            raise
    
    def get_iv(self) -> str:
        logger.debug("Extracting IV from PYE file")
        try:
            iv = b85dectohex(self.lines[1]) # First line is IV
            logger.debug("Successfully extracted IV")
            return iv
        except Exception as e:
            logger.error(f"Failed to extract IV: {str(e)}")
            raise

    def get_ciphertext(self) -> str: # The rest is CipherText
        logger.debug("Extracting ciphertext from PYE file")
        try:
            ciphertext = b85dectohex(''.join(self.lines[2 : len(self.lines) - 1]))
            logger.debug(f"Successfully extracted ciphertext ({len(ciphertext)} characters)")
            return ciphertext
        except Exception as e:
            logger.error(f"Failed to extract ciphertext: {str(e)}")
            raise


def b85dectohex(text: str):
    logger.debug("Converting base85 to hex")
    prepared = text.replace("\n", "").replace(" ", "")
    # print(prepared)
    try:
        result = b85decode(prepared).hex().upper()
        logger.debug("Successfully decoded using b85decode")
    except Exception as e:
        # print(f"error: {e}, maybe zlib..")
        logger.debug(f"b85decode failed ({str(e)}), trying zlib decompression")
        try:
            result = zlib.decompress(a85decode(prepared)).hex().upper()
            logger.debug("Successfully decoded using zlib decompression")
        except Exception as e2:
            logger.error(f"Both decoding methods failed: {str(e2)}")
            raise

    return result


def unprotect_sourcedefender_file(pye_file: str | Path, key_hex: str = None) -> dict:
    """
    Main function to unprotect a SourceDefender file.
    
    Args:
        pye_file (str | Path): Path to the .pye file
        key_hex (str, optional): Hexadecimal key. If None, will be derived from filename
        
    Returns:
        dict: Dictionary containing unprotection results
    """
    logger.info(f"Starting SourceDefender unprotection for file: {pye_file}")
    
    try:
        # Skip redundant check since we know it's already a SourceDefender file
        if key_hex is None:
            key_hex = derive_aes_key(pye_file)
            
        pye = PYE_Processor(pye_file)
        iv_hex = pye.get_iv()
        ciphertext_hex = pye.get_ciphertext()
        
        unprotect_module = Unprotect(pye_file, key_hex, iv_hex, ciphertext_hex)
        result = unprotect_module.unprotect()
        
        if result['success']:
            logger.info("SourceDefender unprotection completed successfully")
        else:
            logger.error(f"SourceDefender unprotection failed: {result.get('error', 'Unknown error')}")
            
        return result
        
    except Exception as e:
        error_msg = f"SourceDefender unprotection failed: {str(e)}"
        logger.error(error_msg)
        return {
            'success': False,
            'error': error_msg,
            'version': None,
            'output_file': None,
            'file_type': None
        }

def derive_aes_key(file_path):
    logger.debug(f"Deriving AES key for file: {file_path}")
    try:
        base_name = os.path.splitext(os.path.basename(file_path))[0].encode()
        key = hashlib.blake2b(base_name, digest_size=64).digest()
        salt = hashlib.blake2b(base_name, digest_size=16).digest()
        derived_key = hashlib.blake2b(key=key, salt=salt, digest_size=32).hexdigest()
        logger.debug("Successfully derived AES key")
        return derived_key
    except Exception as e:
        logger.error(f"Failed to derive AES key: {str(e)}")
        raise


def get_sourcedefender_info(pye_file: str | Path) -> dict:
    """
    Get information about a SourceDefender protected file without decrypting it.
    
    Args:
        pye_file (str | Path): Path to the .pye file
        
    Returns:
        dict: Dictionary containing file information
    """
    logger.info(f"Getting SourceDefender file info for: {pye_file}")
    
    info = {
        'file_exists': False,
        'file_size': 0,
        'line_count': 0,
        'derived_key': None,
        'error': None
    }
    
    try:
        info['file_exists'] = os.path.exists(pye_file)
        if not info['file_exists']:
            info['error'] = 'File does not exist'
            return info
            
        info['file_size'] = os.path.getsize(pye_file)
        
        # Since we already know it's SourceDefender, get info directly
        with open(pye_file, 'r') as f:
            info['line_count'] = len(f.readlines())
        info['derived_key'] = derive_aes_key(pye_file)
            
        logger.debug(f"File info retrieved successfully for: {pye_file}")
        return info
        
    except Exception as e:
        info['error'] = str(e)
        logger.error(f"Failed to get file info: {str(e)}")
        return info
