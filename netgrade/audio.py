import logging
import os
import hashlib
import httpx
from typing import List, Optional
from netgrade.models import CheckResult

logger = logging.getLogger(__name__)

#: ElevenLabs retired eleven_monolingual_v1. The deployed instance was calling
#: it, getting HTTP 400 back, and falling through to the silent fallback -- so
#: every briefing was 504 bytes of nothing behind a working play button. Flash
#: is the fastest current model and the briefing text is English.
DEFAULT_MODEL_ID = "eleven_flash_v2_5"


def _load_dotenv():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(root_dir, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v


class ElevenLabsAudioGenerator:
    """
    Generates plain-language audio briefings summarizing top risks.
    Caches output locally to avoid API invocation during live recorded demos.
    """
    def __init__(self, api_key: Optional[str] = None, voice_id: str = "21m00Tcm4TlvDq8ikWAM",
                 model_id: str = DEFAULT_MODEL_ID):
        _load_dotenv()
        self.api_key = api_key or os.getenv("ELEVENLABS_API_KEY")
        self.voice_id = voice_id
        self.model_id = model_id
        self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "audio_cache")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _build_briefing_text(self, domain: str, grade: str, score: int, checks: List[CheckResult]) -> str:
        failing_checks = [c for c in checks if c.status in ["fail", "warn"]]
        if not failing_checks:
            return f"Security posture briefing for {domain}. Excellent posture with grade {grade} and score of {score}. All passive risk controls passed."

        top_risks = sorted(failing_checks, key=lambda c: 0 if c.severity == "critical" else (1 if c.severity == "high" else 2))[:3]
        summaries = [f"{c.title}: {c.summary}" for c in top_risks]

        return (
            f"Security briefing for {domain}. Current posture grade is {grade} with a score of {score} out of 100. "
            f"Your top priority risks are: {'; '.join(summaries)}. "
            f"Focus on resolving your highest severity issue first."
        )

    def _generate_fallback_audio(self, filepath: str, text: str) -> str | None:
        """Synthesizes real spoken audio locally via SAPI or sample briefing wav when ElevenLabs API key is absent."""
        wav_path = filepath.rsplit(".", 1)[0] + ".wav"
        
        # 1. Try local Windows Speech Synthesizer for dynamic spoken audio
        try:
            import subprocess
            clean_text = text.replace("'", "").replace('"', "")
            ps_cmd = (
                f"Add-Type -AssemblyName System.Speech; "
                f"$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                f"$s.SetOutputToWaveFile('{wav_path}'); "
                f"$s.Speak('{clean_text}'); "
                f"$s.Dispose()"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(wav_path) and os.path.getsize(wav_path) > 5000:
                return f"/static/audio_cache/{os.path.basename(wav_path)}"
        except Exception:
            pass

        # 2. Fallback to pre-synthesized sample briefing wav
        sample_wav = os.path.join(self.cache_dir, "sample_briefing.wav")
        if os.path.exists(sample_wav):
            import shutil
            shutil.copy(sample_wav, wav_path)
            return f"/static/audio_cache/{os.path.basename(wav_path)}"

        # 3. Nothing could be synthesised. This used to write 500 zeroed mp3
        # frames and return their URL, which rendered a play button over
        # silence. No URL is the honest answer: the template omits the player.
        logger.warning("no briefing audio available for %s", os.path.basename(filepath))
        return None

    async def get_or_generate_audio(
        self, domain: str, grade: str, score: int, checks: List[CheckResult]
    ) -> str | None:
        text = self._build_briefing_text(domain, grade, score, checks)
        text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        filename = f"briefing_{domain}_{text_hash[:10]}.mp3"
        filepath = os.path.join(self.cache_dir, filename)
        wav_path = os.path.join(self.cache_dir, f"briefing_{domain}_{text_hash[:10]}.wav")

        # Return cached audio URL if present
        if os.path.exists(wav_path) and os.path.getsize(wav_path) > 5000:
            return f"/static/audio_cache/{os.path.basename(wav_path)}"
        if os.path.exists(filepath) and os.path.getsize(filepath) > 5000:
            return f"/static/audio_cache/{filename}"

        # If ElevenLabs API Key is present, invoke API
        if self.api_key:
            try:
                url = f"https://api.elevenlabs.io/v1/text-to-speech/{self.voice_id}"
                headers = {
                    "Accept": "audio/mpeg",
                    "Content-Type": "application/json",
                    "xi-api-key": self.api_key
                }
                data = {
                    "text": text,
                    "model_id": self.model_id,
                    "voice_settings": {"stability": 0.5, "similarity_boost": 0.75}
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(url, json=data, headers=headers)
                    if res.status_code == 200 and len(res.content) > 1000:
                        with open(filepath, "wb") as f:
                            f.write(res.content)
                        logger.info(
                            "synthesised briefing for %s: %d bytes via %s",
                            domain, len(res.content), self.model_id,
                        )
                        return f"/static/audio_cache/{filename}"
                    # A non-200 raises nothing, so the except below never saw
                    # it -- the failure was discarded by this if having no
                    # else. The body carries the reason; log it.
                    logger.error(
                        "ElevenLabs refused the briefing for %s: HTTP %s %s",
                        domain, res.status_code, res.text[:500],
                    )
            except Exception:
                logger.exception("ElevenLabs call failed for %s", domain)
        else:
            logger.error("ELEVENLABS_API_KEY is not set; no briefing can be synthesised")

        # Synthesize real spoken audio fallback for local offline testing
        return self._generate_fallback_audio(filepath, text)
