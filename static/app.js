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
    if (!card.hasAttribute('tabindex')) {
      card.setAttribute('tabindex', '0');
    }
  });

  // Anti-Spam Form Submission Prevention & Loading Indicators
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      if (form.dataset.submitting === 'true') {
        e.preventDefault();
        return;
      }
      form.dataset.submitting = 'true';

      const submitBtn = form.querySelector('button[type="submit"]');
      if (!submitBtn) return;

      const isCompare = form.action.includes('/compare');
      const loadingText = isCompare ? 'Comparing Postures...' : 'Auditing Posture...';

      submitBtn.classList.add('is-loading');
      submitBtn.disabled = true;
      submitBtn.style.pointerEvents = 'none';

      const btnSpan = submitBtn.querySelector('span');
      if (btnSpan) {
        btnSpan.textContent = loadingText;
      }

      // Replace or prepend animated spinner icon
      let svg = submitBtn.querySelector('svg');
      const spinnerSvg = `<svg class="spinner-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>`;
      if (svg) {
        svg.outerHTML = spinnerSvg;
      } else {
        submitBtn.insertAdjacentHTML('afterbegin', spinnerSvg);
      }

      // Activate scan progress overlay if present
      const overlay = document.getElementById('scan-progress-overlay');
      if (overlay) {
        overlay.classList.add('is-active');
        const overlayText = overlay.querySelector('.scan-progress-text');
        
        const steps = [
          'Resolving DNS & MX records...',
          'Performing TLS/SSL handshake...',
          'Inspecting Security Headers & CSP...',
          'Checking Session Cookie flags...',
          'Auditing Exposed Files (.git / .env)...',
          'Querying Certificate Transparency logs...',
          'Synthesizing final risk score & briefing...'
        ];
        
        let stepIdx = 0;
        setInterval(() => {
          stepIdx = (stepIdx + 1) % steps.length;
          if (overlayText) {
            overlayText.textContent = steps[stepIdx];
          }
        }, 1100);
      }
    });
  });

  // Handle Live Re-Scan Action Button Loading State
  const rescanBtns = document.querySelectorAll('.js-rescan-btn');
  rescanBtns.forEach(btn => {
    btn.addEventListener('click', function(e) {
      if (this.dataset.clicked === 'true') {
        e.preventDefault();
        return;
      }
      this.dataset.clicked = 'true';
      this.classList.add('is-loading');
      this.style.pointerEvents = 'none';
      const span = this.querySelector('span');
      if (span) span.textContent = 'Re-Scanning...';
    });
  });
});
