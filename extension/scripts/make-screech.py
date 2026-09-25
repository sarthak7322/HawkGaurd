"""Synthesise HawkGuard's alert sound: a red-tailed-hawk style "kee-eeeer" screech.

Our own sound (no copyrighted meme clip). Replace src/assets/hawk-screech.wav with any
other short clip to change it. Run: python3 scripts/make-screech.py
"""
import wave
import numpy as np
from scipy.signal import butter, sosfilt

SR = 22050
rng = np.random.default_rng(7)

def screech(dur=1.7, f_peak=3300, f_end=1900):
    t = np.arange(int(SR * dur)) / SR
    # Pitch: quick rise into the peak, then a long slide down, with a nervous wobble
    rise = 0.1
    f = np.where(t < rise, 2400 + (f_peak - 2400) * (t / rise) ** 0.6,
                 f_end + (f_peak - f_end) * np.exp(-(t - rise) * 1.9))
    f *= 1 + 0.018 * np.sin(2 * np.pi * 11 * t)
    phase = 2 * np.pi * np.cumsum(f) / SR
    # Harsh, buzzy tone: stacked harmonics, amplitude-roughened like a strained syrinx
    tone = sum(np.sin(k * phase) / k ** 0.9 for k in range(1, 6))
    rough = 1 + 0.55 * np.sign(np.sin(2 * np.pi * 95 * t)) * (0.5 + 0.5 * np.sin(2 * np.pi * 3 * t))
    # Breath/rasp: noise band-passed around the pitch region
    noise = sosfilt(butter(4, [1500, 5200], 'bandpass', fs=SR, output='sos'), rng.standard_normal(t.size))
    sig = tone * rough * 0.7 + noise * 2.2 * (0.4 + 0.6 * (t > rise))
    env = np.minimum(1, t / 0.03) * np.clip((dur - t) / 0.55, 0, 1) ** 1.4
    return sig * env

# "kee-EEEEER" plus a short second call, like the movie version
call = np.concatenate([screech(), np.zeros(int(SR * 0.08)), screech(0.9, 3100, 2200) * 0.6])
# Echo off a canyon wall, for the meme
out = call.copy()
for delay, gain in [(0.19, 0.38), (0.41, 0.18)]:
    d = int(SR * delay)
    out = np.concatenate([out, np.zeros(d)])
    out[d:d + call.size] += call * gain
out = sosfilt(butter(2, 700, 'highpass', fs=SR, output='sos'), out)
out = out / np.max(np.abs(out)) * 0.85
out = np.concatenate([np.zeros(int(SR * 0.02)), out])

with wave.open('src/assets/hawk-screech.wav', 'wb') as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR)
    w.writeframes((out * 32767).astype('<i2').tobytes())
print(f'wrote src/assets/hawk-screech.wav · {out.size / SR:.2f}s')
