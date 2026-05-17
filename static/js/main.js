// CSRF Token Helper
function getCsrfToken() {
  const el = document.querySelector('input[name="csrf_token"]');
  return el ? el.value : '';
}

// DevTools Detection (Basic)
let devtoolsOpen = false;
const threshold = 160;

setInterval(() => {
  const widthThreshold = window.outerWidth - window.innerWidth > threshold;
  const heightThreshold = window.outerHeight - window.innerHeight > threshold;
  if (widthThreshold || heightThreshold) {
    if (!devtoolsOpen) {
      devtoolsOpen = true;
      document.body.innerHTML = '<div style="padding:40px;text-align:center;font-family:sans-serif;background:#F9FAFB;height:100vh;display:flex;align-items:center;justify-content:center;"><div><h1 style="color:#DC2626;margin-bottom:12px;">Akses Dihentikan</h1><p style="color:#6B7280;">Terdeteksi aktivitas mencurigakan pada browser.</p></div></div>';
    }
  } else {
    devtoolsOpen = false;
  }
}, 1200);

// Radio Button Active State Enhancement
document.querySelectorAll('.radio-option input[type="radio"]').forEach(radio => {
  radio.addEventListener('change', function() {
    document.querySelectorAll('.radio-option').forEach(opt => opt.classList.remove('active'));
    if (this.checked) {
      this.closest('.radio-option').classList.add('active');
    }
  });
  if (radio.checked) {
    radio.closest('.radio-option').classList.add('active');
  }
});
