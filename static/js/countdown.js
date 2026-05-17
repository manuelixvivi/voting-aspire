/**
 * Live Countdown Timer for Student Dashboard
 * Usage: <div id="timer" data-ds-id="123"></div>
 * Then call: initCountdown('timer')
 */
function initCountdown(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const dsId = el.dataset.dsId;
    if (!dsId) {
        console.error('Countdown: data-ds-id attribute missing');
        return;
    }

    function updateTimer() {
        fetch('/api/time-remaining/' + dsId)
            .then(r => {
                if (!r.ok) throw new Error('Network error');
                return r.json();
            })
            .then(data => {
                if (data.is_expired) {
                    el.innerHTML = '<span class="text-danger fw-bold">WAKTU HABIS</span>';
                    el.classList.add('expired');
                    document.querySelectorAll('form button[type="submit"]').forEach(btn => {
                        btn.disabled = true;
                        btn.innerText = 'Waktu Habis';
                    });
                    return;
                }

                if (data.remaining) {
                    const r = data.remaining;
                    const parts = [];
                    if (r.days > 0) parts.push(r.days + ' hari');
                    if (r.hours > 0) parts.push(r.hours + ' jam');
                    if (r.minutes > 0) parts.push(r.minutes + ' menit');
                    parts.push(r.seconds + ' detik');

                    el.innerHTML = parts.join(' : ');

                    if (r.total_seconds < 3600) {
                        el.classList.add('text-danger', 'fw-bold');
                    } else if (r.total_seconds < 86400) {
                        el.classList.add('text-warning', 'fw-bold');
                    }
                } else {
                    el.innerHTML = 'Tidak ada batas waktu';
                }
            })
            .catch(err => {
                console.error('Countdown error:', err);
                el.innerHTML = '--:--:--';
            });
    }

    updateTimer();
    setInterval(updateTimer, 1000);
}
