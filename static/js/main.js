/* ==========================================
   STEGOEYE CLIENT SCRIPT - CORE FRONTEND LOGIC
   ========================================== */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initial setups and UI toggles
    initDragAndDrop();
    initLoader();
    
    // Check if on home page vs action page
    const encodeForm = document.getElementById('encode-form');
    const decodeForm = document.getElementById('decode-form');
    const analyzeForm = document.getElementById('analyze-form');
    
    if (encodeForm) initEncode(encodeForm);
    if (decodeForm) initDecode(decodeForm);
    if (analyzeForm) initAnalyze(analyzeForm);
});

/* ==========================================
   LOADER LOGIC
   ========================================== */
function initLoader() {
    const loader = document.getElementById('loader');
    const loaderText = document.getElementById('loader-text');
    
    window.showLoader = (text = "Processing secure algorithms...") => {
        if (loader) {
            if (loaderText) loaderText.textContent = text;
            loader.style.display = 'flex';
        }
    };
    
    window.hideLoader = () => {
        if (loader) loader.style.display = 'none';
    };
}

/* ==========================================
   DRAG AND DROP HANDLER
   ========================================== */
function initDragAndDrop() {
    const uploadZones = document.querySelectorAll('.upload-zone');
    
    uploadZones.forEach(zone => {
        const input = zone.querySelector('.file-input');
        
        // Click to open file explorer
        zone.addEventListener('click', () => input.click());
        
        // Input change
        input.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleUploadedFile(e.target.files[0], zone);
            }
        });
        
        // Drag over states
        ['dragenter', 'dragover'].forEach(eventName => {
            zone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                zone.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                zone.classList.remove('dragover');
            }, false);
        });
        
        // Drop file
        zone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                input.files = files; // Sync input
                // Fire change event so the input listener and active file variables sync correctly
                input.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });
    });
}

function handleUploadedFile(file, zone) {
    const previewImg = document.querySelector('.img-preview-target');
    const previewContainer = document.querySelector('.preview-wrapper');
    const infoTag = document.querySelector('.image-info-tag');
    const uploadPrompt = zone.querySelector('.upload-prompt');
    const placeholders = document.querySelectorAll('#cover-placeholder, #stego-placeholder');
    
    if (!file.type.match('image.*')) {
        alert('Please upload an image file (PNG, JPG, BMP, etc.).');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => {
        if (previewImg) {
            previewImg.src = e.target.result;
            previewImg.style.display = 'block';
        }
        if (previewContainer) previewContainer.style.display = 'flex';
        
        // Hide initial placeholders
        placeholders.forEach(p => p.style.display = 'none');
        
        if (uploadPrompt) {
            uploadPrompt.innerHTML = `<strong>Selected:</strong> ${file.name}<br><span class="text-secondary">Click or drag a new image to replace</span>`;
        }
        
        // Expose metadata tags on UI
        if (infoTag) {
            const img = new Image();
            img.onload = function() {
                infoTag.textContent = `${file.name} | ${this.width} x ${this.height} px | ${(file.size / 1024).toFixed(1)} KB`;
                infoTag.style.display = 'inline-block';
            };
            img.src = e.target.result;
        }
    };
    reader.readAsDataURL(file);
    
    // If we are in the interactive steganalysis pane, clear out old results when a new file is uploaded
    const resultBox = document.getElementById('analysis-results-box');
    if (resultBox) resultBox.style.display = 'none';
}

/* ==========================================
   STEGO ENCODING
   ========================================== */
function initEncode(form) {
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const fileInput = document.getElementById('image-upload');
        if (!fileInput.files || fileInput.files.length === 0) {
            alert("Please upload a cover image first!");
            return;
        }
        
        const formData = new FormData(form);
        showLoader("Embedding secret message and compiling matrix...");
        
        try {
            const response = await fetch('/encode', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            
            hideLoader();
            
            if (result.success) {
                const resultBox = document.getElementById('encode-result-box');
                const outImg = document.getElementById('stego-output-image');
                const downloadBtn = document.getElementById('download-stego-btn');
                
                // Show stego preview image
                outImg.src = `data:image/png;base64,${result.image_b64}`;
                outImg.style.display = 'block';
                
                // Configure download action
                downloadBtn.href = `data:image/png;base64,${result.image_b64}`;
                downloadBtn.download = result.filename;
                
                resultBox.style.display = 'block';
                resultBox.scrollIntoView({ behavior: 'smooth' });
            } else {
                alert(result.error || "An error occurred during encoding.");
            }
        } catch (err) {
            hideLoader();
            alert("Network error: Failed to connect to server.");
            console.error(err);
        }
    });
}

/* ==========================================
   STEGO DECODING
   ========================================== */
function initDecode(form) {
    const passwordGroup = document.getElementById('password-reveal-group');
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const fileInput = document.getElementById('image-upload');
        if (!fileInput.files || fileInput.files.length === 0) {
            alert("Please upload an image to decode!");
            return;
        }
        
        const formData = new FormData(form);
        showLoader("Extracting bits from LSB indices...");
        
        try {
            const response = await fetch('/decode', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            
            hideLoader();
            
            const resultBox = document.getElementById('decode-result-box');
            const alertText = document.getElementById('decode-alert-text');
            const messageOutputBox = document.getElementById('message-output-box');
            const secretTextArea = document.getElementById('extracted-secret-message');
            
            if (result.status === 'success') {
                // Succeeded in extraction
                alertText.className = "severity-banner banner-success";
                alertText.innerHTML = "🔓 SECURE PAYLOAD DECODED SUCCESSFULLY!";
                secretTextArea.value = result.message;
                messageOutputBox.style.display = 'block';
                resultBox.style.display = 'block';
                resultBox.scrollIntoView({ behavior: 'smooth' });
            } else if (result.status === 'password_required') {
                // Show password field
                alertText.className = "severity-banner banner-warning";
                alertText.innerHTML = "🔑 PASSWORD ENCRYPTION DETECTED";
                passwordGroup.style.display = 'block';
                messageOutputBox.style.display = 'none';
                resultBox.style.display = 'block';
                resultBox.scrollIntoView({ behavior: 'smooth' });
                alert("This payload is encrypted. Please enter the password above and click Extract again.");
            } else {
                // Errors
                alertText.className = "severity-banner banner-danger";
                alertText.innerHTML = "⚠️ DECODING ERROR";
                secretTextArea.value = result.error || "An unknown error occurred during decoding.";
                messageOutputBox.style.display = 'block';
                resultBox.style.display = 'block';
                resultBox.scrollIntoView({ behavior: 'smooth' });
            }
        } catch (err) {
            hideLoader();
            alert("Network error: Failed to connect to server.");
            console.error(err);
        }
    });
}

/* ==========================================
   ADVANCED STEGANALYSIS (DETECTION)
   ========================================== */
function initAnalyze(form) {
    let currentImageFile = null;
    let activeChannel = 'Red';
    let activeDepth = 0;
    
    // Capture file whenever user changes it so we can run on-the-fly bitplane renders
    const fileInput = document.getElementById('image-upload');
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            currentImageFile = e.target.files[0];
        }
    });
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!currentImageFile) {
            alert("Please upload a suspicious image to analyze!");
            return;
        }
        
        const formData = new FormData(form);
        showLoader("Running statistical tests, metadata scans, and bit plane extractions...");
        
        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            
            hideLoader();
            
            if (result.success) {
                renderAnalysisDashboard(result);
            } else {
                alert(result.error || "Analysis failed.");
            }
        } catch (err) {
            hideLoader();
            alert("Network error: Failed to connect to server.");
            console.error(err);
        }
    });
    
    // RENDER RESULTS
    function renderAnalysisDashboard(data) {
        const resultBox = document.getElementById('analysis-results-box');
        
        // 1. Threat score gauge
        updateThreatGauge(data.threat_score, data.severity_class);
        
        // 2. Severity indicator
        const banner = document.getElementById('analysis-severity-banner');
        banner.className = `severity-banner banner-${data.severity_class}`;
        banner.textContent = data.severity;
        
        // 3. Reasons List
        const reasonsList = document.getElementById('analysis-reasons-list');
        reasonsList.innerHTML = '';
        if (data.reasons.length === 0) {
            const item = document.createElement('li');
            item.className = 'reason-item';
            item.textContent = "All scans clean. No statistical LSB anomalies or metadata appended data found.";
            reasonsList.appendChild(item);
        } else {
            data.reasons.forEach(reason => {
                const item = document.createElement('li');
                item.className = `reason-item ${data.severity_class}`;
                item.textContent = reason;
                reasonsList.appendChild(item);
            });
        }
        
        // 4. File details metadata
        const metadata = data.metadata;
        document.getElementById('meta-filename').textContent = metadata.filename;
        document.getElementById('meta-format').textContent = metadata.format;
        document.getElementById('meta-resolution').textContent = `${metadata.width} x ${metadata.height} px`;
        document.getElementById('meta-filesize').textContent = formatBytes(metadata.raw_file_size);
        document.getElementById('meta-pixelbytes').textContent = formatBytes(metadata.pixel_bytes);
        
        // 5. EXIF table
        const exifList = document.getElementById('meta-exif-list');
        exifList.innerHTML = '';
        const exifKeys = Object.keys(metadata.exif);
        if (exifKeys.length === 0) {
            exifList.innerHTML = '<tr><td colspan="2" class="text-secondary" style="text-align: center; padding: 1rem;">No EXIF metadata fields available in this image.</td></tr>';
        } else {
            exifKeys.forEach(key => {
                const row = document.createElement('tr');
                row.innerHTML = `<td class="label">${key}</td><td class="value">${metadata.exif[key]}</td>`;
                exifList.appendChild(row);
            });
        }
        
        // 6. Trailing bytes report
        const tbBox = document.getElementById('trailing-bytes-section');
        const tbData = metadata.trailing_bytes;
        if (tbData.found) {
            document.getElementById('tb-length').textContent = `${tbData.length} Bytes`;
            document.getElementById('tb-hex').textContent = tbData.hex_preview;
            document.getElementById('tb-text').textContent = tbData.text_preview;
            
            // Setup direct file download of trailing bytes
            const downloadLink = document.getElementById('download-tb-btn');
            downloadLink.href = `data:application/octet-stream;base64,${tbData.base64}`;
            downloadLink.download = `extracted_stego_appended_bytes.bin`;
            
            tbBox.style.display = 'block';
        } else {
            tbBox.style.display = 'none';
        }
        
        // 7. Render initial static LSB bitplanes
        document.getElementById('bitplane-viewer-r').src = `data:image/png;base64,${data.bit_planes.Red}`;
        document.getElementById('bitplane-viewer-g').src = `data:image/png;base64,${data.bit_planes.Green}`;
        document.getElementById('bitplane-viewer-b').src = `data:image/png;base64,${data.bit_planes.Blue}`;
        
        // Reset active plane tracking
        activeChannel = 'Red';
        activeDepth = 0;
        document.getElementById('plane-depth-slider').value = 0;
        document.getElementById('slider-depth-val').textContent = 'Bit 0 (LSB)';
        
        // Make results visible
        resultBox.style.display = 'block';
        resultBox.scrollIntoView({ behavior: 'smooth' });
    }
    
    // DYNAMIC BIT PLANE INTERACTIVE REQUESTS
    const depthSlider = document.getElementById('plane-depth-slider');
    const tabButtons = document.querySelectorAll('.bitplane-tabs .tab-btn');
    
    depthSlider.addEventListener('input', (e) => {
        const depth = parseInt(e.target.value);
        activeDepth = depth;
        document.getElementById('slider-depth-val').textContent = depth === 0 ? 'Bit 0 (LSB)' : depth === 7 ? 'Bit 7 (MSB)' : `Bit ${depth}`;
        triggerBitPlaneUpdate();
    });
    
    tabButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeChannel = btn.dataset.channel;
            
            // Also toggle visible image box
            document.querySelectorAll('.bitplane-panes .tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            const targetPane = document.getElementById(`pane-${activeChannel.toLowerCase()}`);
            if (targetPane) targetPane.classList.add('active');
            
            triggerBitPlaneUpdate();
        });
    });
    
    async function triggerBitPlaneUpdate() {
        if (!currentImageFile) return;
        
        const sliderGlow = document.getElementById('slider-depth-val');
        sliderGlow.style.opacity = '0.5'; // Visual throttle indicator
        
        const requestData = new FormData();
        requestData.append('image', currentImageFile);
        requestData.append('channel', activeChannel);
        requestData.append('depth', activeDepth);
        
        try {
            const res = await fetch('/get_plane', {
                method: 'POST',
                body: requestData
            });
            const result = await res.json();
            
            sliderGlow.style.opacity = '1';
            
            if (result.success) {
                const activeImg = document.getElementById(`bitplane-viewer-${activeChannel.toLowerCase().charAt(0)}`);
                if (activeImg) {
                    activeImg.src = `data:image/png;base64,${result.image_b64}`;
                }
            }
        } catch (err) {
            sliderGlow.style.opacity = '1';
            console.error("Failed to update bitplane dynamically:", err);
        }
    }
}

/* ==========================================
   SVG THREAT GAUGE ANIMATOR
   ========================================== */
function updateThreatGauge(score, severityClass) {
    const gaugeFill = document.querySelector('.gauge-fill');
    const gaugeValue = document.querySelector('.gauge-value');
    const container = document.querySelector('.threat-gauge-container');
    
    if (!gaugeFill || !gaugeValue) return;
    
    // Set dynamic attribute for CSS styling colors
    if (container) container.setAttribute('data-severity', severityClass);
    
    // Calculate SVG Stroke offset
    // Radius = 90. Perimeter = 2 * PI * 90 = 565.486
    const r = 90;
    const c = 2 * Math.PI * r;
    
    // Score bound checks
    score = Math.max(0, Math.min(100, score));
    
    const offset = c - (score / 100) * c;
    
    // Apply stroke dashoffset
    gaugeFill.style.strokeDashoffset = offset;
    
    // Animate the text counting up
    let startVal = 0;
    const duration = 1000; // 1 second animation
    const startTime = performance.now();
    
    function animateText(timestamp) {
        const elapsed = timestamp - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function out-quad
        const easeProgress = progress * (2 - progress);
        const currentVal = Math.floor(easeProgress * score);
        
        gaugeValue.textContent = `${currentVal}%`;
        
        if (progress < 1) {
            requestAnimationFrame(animateText);
        } else {
            gaugeValue.textContent = `${score}%`;
        }
    }
    
    requestAnimationFrame(animateText);
}

/* ==========================================
   UI HELPER UTILITIES
   ========================================== */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
