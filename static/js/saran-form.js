
function selectTawaran(id) {
    // Reset all cards
    document.querySelectorAll('.tawaran-card').forEach(c => {
        c.style.borderColor = '#E5E7EB';
        c.style.background = 'white';
    });
    document.querySelectorAll('input[name="pilihan"]').forEach(r => r.checked = false);

    const radio = document.getElementById(id);
    if (!radio) return;
    radio.checked = true;

    const card = document.getElementById('card-' + id);
    const wrapper = document.getElementById('divisi-custom-wrapper');
    const hiddenInput = document.getElementById('tawaran_diterima');

    if (id === 'tolak') {
        card.style.borderColor = '#DC2626';
        card.style.background = '#FEF2F2';
        if (wrapper) wrapper.style.display = 'block';
        if (hiddenInput) hiddenInput.value = '';
        const divisiCustom = document.getElementById('divisi_custom');
        if (divisiCustom) divisiCustom.required = true;
    } else {
        card.style.borderColor = '#2563EB';
        card.style.background = '#EFF6FF';
        if (wrapper) wrapper.style.display = 'none';
        // Get the tawaran title from the card's tawaran-title element
        const titleEl = card.querySelector('.tawaran-title');
        if (titleEl && hiddenInput) {
            hiddenInput.value = titleEl.textContent.trim();
        }
        const divisiCustom = document.getElementById('divisi_custom');
        if (divisiCustom) divisiCustom.required = false;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('input[name="pilihan"]').forEach(radio => {
        radio.addEventListener('change', function() {
            selectTawaran(this.id);
        });
    });

    const form = document.getElementById('saranForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            const pilihan = document.querySelector('input[name="pilihan"]:checked');
            if (!pilihan) {
                e.preventDefault();
                alert('Silakan pilih salah satu opsi.');
                return false;
            }

            // Debug: log the tawaran_diterima value
            const hiddenInput = document.getElementById('tawaran_diterima');
            console.log('Selected tawaran:', pilihan.id);
            console.log('Hidden value:', hiddenInput ? hiddenInput.value : 'null');

            if (pilihan.id === 'tolak') {
                const divisi = document.getElementById('divisi_custom').value;
                const alasan = document.querySelector('textarea[name="alasan_penolakan"]').value.trim();
                if (!divisi) {
                    e.preventDefault();
                    alert('Silakan pilih divisi tujuan.');
                    return false;
                }
                if (alasan.length < 10) {
                    e.preventDefault();
                    alert('Alasan penolakan minimal 10 karakter.');
                    return false;
                }
            } else {
                // For accept, ensure tawaran_diterima is filled
                if (!hiddenInput || !hiddenInput.value.trim()) {
                    e.preventDefault();
                    alert('Error: Tawaran tidak terdeteksi. Silakan pilih ulang.');
                    return false;
                }
            }
        });
    }
});
