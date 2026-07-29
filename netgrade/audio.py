import os
import hashlib
import httpx
from typing import List, Optional
from netgrade.models import CheckResult


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
    def __init__(self, api_key: Optional[str] = None, voice_id: str = "21m00Tcm4TlvDq8ikWAM"):
        _load_dotenv()
        self.api_key = api_key or os.getenv("ELEVENLABS_API_KEY")
        self.voice_id = voice_id
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

    async def get_or_generate_audio(self, domain: str, grade: str, score: int, checks: List[CheckResult]) -> str:
        text = self._build_briefing_text(domain, grade, score, checks)
        text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        filename = f"briefing_{domain}_{text_hash[:10]}.mp3"
        filepath = os.path.join(self.cache_dir, filename)

        # Return cached audio URL if present
        if os.path.exists(filepath):
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
                    "model_id": "eleven_monolingual_v1",
                    "voice_settings": {"stability": 0.5, "similarity_boost": 0.75}
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(url, json=data, headers=headers)
                    if res.status_code == 200:
                        with open(filepath, "wb") as f:
                            f.write(res.content)
                        return f"/static/audio_cache/{filename}"
            except Exception:
                pass

        # Fallback: create silent/demo mp3 file fixture if offline
        with open(filepath, "wb") as f:
            # Minimal MP3 frame header representation
            f.write(b'\xff\xf3\x44\xc4' + b'\x00' * 500)

        return f"/static/audio_cache/{filename}"
