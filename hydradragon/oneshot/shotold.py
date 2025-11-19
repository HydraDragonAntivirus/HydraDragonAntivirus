import os
import asyncio
import logging
import traceback
from typing import Dict, List, Tuple
from Crypto.Cipher import AES

try:
    from colorama import init, Fore, Style
except ImportError:
    def init(**kwargs): pass
    class Fore: CYAN = RED = YELLOW = GREEN = ''
    class Style: RESET_ALL = ''

from .detect import detect_process
from .runtime import RuntimeInfo

# Initialize colorama
init(autoreset=True)


def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)


async def process_file_python(path: str, data: bytes, runtime: RuntimeInfo,
                              output_dir: str = None, export_raw: bool = True):
    """
    Decrypt a single file purely in Python, without calling external executable.
    """
    logger = logging.getLogger('shot')
    try:
        serial_number = data[2:8].decode('utf-8')
        logger.info(f'{Fore.CYAN}Decrypting: {serial_number} ({path}){Style.RESET_ALL}')

        dest_path = os.path.join(output_dir, path) if output_dir else path
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        if export_raw:
            with open(dest_path + '.1shot.raw', 'wb') as f:
                f.write(data)

        # Handle BCC mode
        if int.from_bytes(data[20:24], 'little') == 9:
            cipher_text_offset = int.from_bytes(data[28:32], 'little')
            cipher_text_length = int.from_bytes(data[32:36], 'little')
            nonce = data[36:40] + data[44:52]
            bcc_aes_decrypted = general_aes_ctr_decrypt(
                data[cipher_text_offset:cipher_text_offset + cipher_text_length],
                runtime.runtime_aes_key, nonce
            )
            data = data[int.from_bytes(data[56:60], 'little'):]
            arch_map = {0x2001: 'win-x64', 0x2003: 'linux-x64'}
            while len(bcc_aes_decrypted) >= 16:
                offset = int.from_bytes(bcc_aes_decrypted[0:4], 'little')
                length = int.from_bytes(bcc_aes_decrypted[4:8], 'little')
                arch_id = int.from_bytes(bcc_aes_decrypted[8:12], 'little')
                next_offset = int.from_bytes(bcc_aes_decrypted[12:16], 'little')
                arch = arch_map.get(arch_id, f'0x{arch_id:x}')
                bcc_file_path = f'{dest_path}.1shot.bcc.{arch}.elf'
                with open(bcc_file_path, 'wb') as f:
                    f.write(bcc_aes_decrypted[offset:offset + length])
                logger.info(f'{Fore.GREEN}Extracted BCC native: {bcc_file_path}{Style.RESET_ALL}')
                if next_offset == 0:
                    break
                bcc_aes_decrypted = bcc_aes_decrypted[next_offset:]

        # Decrypt main payload
        cipher_text_offset = int.from_bytes(data[28:32], 'little')
        cipher_text_length = int.from_bytes(data[32:36], 'little')
        nonce = data[36:40] + data[44:52]
        decrypted = general_aes_ctr_decrypt(
            data[cipher_text_offset:cipher_text_offset + cipher_text_length],
            runtime.runtime_aes_key, nonce
        )

        # Save final Python output
        final_path = dest_path + '.1shot.dec'
        with open(final_path, 'wb') as f:
            f.write(data[:cipher_text_offset] + decrypted + data[cipher_text_offset + cipher_text_length:])
        logger.info(f'{Fore.GREEN}Decrypted file saved: {final_path}{Style.RESET_ALL}')

    except Exception as e:
        logger.error(f'{Fore.RED}Decrypt failed: {e} ({path}){Style.RESET_ALL}')
        logger.error(f'{Fore.RED}{traceback.format_exc()}{Style.RESET_ALL}')


async def decrypt_all_python(runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]],
                             output_dir: str = None, concurrent: int = 4):
    semaphore = asyncio.Semaphore(concurrent)
    async def sem_task(path, data):
        async with semaphore:
            serial_number = data[2:8].decode('utf-8')
            runtime = runtimes[serial_number]
            await process_file_python(path, data, runtime, output_dir)

    await asyncio.gather(*(sem_task(path, data) for path, data in sequences))


def run_oneshot_python(directory: str, runtime_paths: List[str], output_dir: str = None):
    """
    Pure-Python entry point: scans directory, loads runtimes, and decrypts all sequences.
    """
    logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(asctime)-28s %(message)s')
    logger = logging.getLogger('shot')

    runtimes: Dict[str, RuntimeInfo] = {}
    for path in runtime_paths:
        rt = RuntimeInfo(path)
        runtimes[rt.serial_number] = rt
        logger.info(f'Loaded runtime: {rt.serial_number} ({path})')

    sequences: List[Tuple[str, bytes]] = []
    for dirpath, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(dirpath, file_name)
            rel_path = os.path.relpath(file_path, directory)
            result = detect_process(file_path, rel_path)
            if result:
                sequences.extend(result)

    if not runtimes:
        raise RuntimeError("No runtime found")
    if not sequences:
        raise RuntimeError("No armored data found")

    asyncio.run(decrypt_all_python(runtimes, sequences, output_dir))
