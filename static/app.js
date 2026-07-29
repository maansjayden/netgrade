/**
 * Netgrade Client JavaScript
 * Progressive enhancement for audio playback, keyboard accessibility, and dynamic UX.
 */

function toggleAudio() {
  const audio = document.getElementById('audio-player');
  const btn = document.getElementById('play-audio-btn');

  if (!audio) return;

  if (audio.paused) {
    audio.play().then(() => {
      if (btn) btn.querySelector('span').textContent = 'Pause Briefing';
    }).catch(err => {
      console.log('Audio playback error:', err);
    });
  } else {
    audio.pause();
    if (btn) btn.querySelector('span').textContent = 'Listen Briefing';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const audio = document.getElementById('audio-player');
  if (audio) {
    audio.addEventListener('ended', () => {
      const btn = document.getElementById('play-audio-btn');
      if (btn) btn.querySelector('span').textContent = 'Listen Briefing';
    });
  }

  const cards = document.querySelectorAll('.card');
  cards.forEach(card => {
    card.setAttribute('tabindex', '0');
  });
});
