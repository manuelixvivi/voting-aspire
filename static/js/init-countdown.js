
// Auto-initialize all countdown timers on page load
document.addEventListener('DOMContentLoaded', function() {
    const countdownEl = document.getElementById('live-countdown');
    if (countdownEl && typeof initCountdown === 'function') {
        initCountdown('live-countdown');
    }
});
