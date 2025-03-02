import numpy as np
import scipy.io.wavfile as wav

# Parameters for the aggressive sound
sample_rate = 44100  # 44.1 kHz standard sample rate
duration = 1.5  # 1.5 seconds
t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)

# Create an aggressive buzzing sound using a mix of square and sawtooth waves
freq1 = 500  # Base frequency
freq2 = 1200  # Higher frequency for aggressiveness

# Square wave (harsh tone)
square_wave = np.sign(np.sin(2 * np.pi * freq1 * t))

# Sawtooth wave (metallic feel)
saw_wave = 2 * (t * freq2 - np.floor(t * freq2 + 0.5))

# Mix both waves and normalize
sound_wave = (square_wave + saw_wave) * 0.5
sound_wave = np.int16(sound_wave / np.max(np.abs(sound_wave)) * 32767)  # Convert to 16-bit PCM

# Save as WAV file
wav_filename = "aggressive_sound.wav"
wav.write(wav_filename, sample_rate, sound_wave)

wav_filename