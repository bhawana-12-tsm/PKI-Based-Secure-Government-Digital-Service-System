// ── File upload UX ────────────────────────────────────────────────────────
document.querySelectorAll('.file-upload-area').forEach(area => {
  const input = area.querySelector('input[type="file"]');
  if (!input) return;

  const fieldId = input.id;
  const previewEl = document.getElementById(`preview-${fieldId}`);

  input.addEventListener('change', () => {
    const file = input.files[0];
    if (file) {
      const sizeMB = (file.size / 1024 / 1024).toFixed(2);
      const inner = area.querySelector('.file-upload-inner');
      inner.innerHTML = `
        <i class="fas fa-check-circle" style="color:var(--success)"></i>
        <p style="color:var(--success)">${file.name}</p>
        <small>${sizeMB} MB</small>
      `;
      area.style.borderColor = 'var(--success)';
      area.style.background = '#f0fdf4';
    }
  });

  // Drag and drop
  area.addEventListener('dragover', (e) => {
    e.preventDefault();
    area.classList.add('dragover');
  });
  area.addEventListener('dragleave', () => area.classList.remove('dragover'));
  area.addEventListener('drop', (e) => {
    e.preventDefault();
    area.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change'));
    }
  });
});

// ── Form submission loading state ─────────────────────────────────────────
const form = document.getElementById('serviceForm');
const submitBtn = document.getElementById('submitBtn');
if (form && submitBtn) {
  form.addEventListener('submit', (e) => {
    // Basic client-side validation
    const fileInputs = form.querySelectorAll('input[type="file"][required]');
    let valid = true;
    fileInputs.forEach(input => {
      if (!input.files.length) {
        valid = false;
        const area = input.closest('.file-upload-area');
        if (area) area.style.borderColor = 'var(--danger)';
      }
    });
    if (!valid) {
      e.preventDefault();
      return;
    }
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Submitting & Signing with PKI...';
  });
}
