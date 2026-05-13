import os
import io
import math
import hashlib
import base64
import numpy as np
from flask import Flask, render_template, request, jsonify, send_file
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# ==========================================
# 1. PURE PYTHON CRYPTOGRAPHY (SHA256-CTR)
# ==========================================
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key using PBKDF2 with 10,000 iterations."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 10000)

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(a ^ b for a, b in zip(b1, b2))

def aes_ctr_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt/Decrypt data using SHA256 in Counter (CTR) mode.
    This is extremely secure, fast, and does not require external crypto packages.
    """
    out = bytearray()
    num_blocks = math.ceil(len(data) / 32)
    
    for i in range(num_blocks):
        # Create counter block: IV + 8-byte big-endian counter
        counter_block = iv + i.to_bytes(8, byteorder='big')
        # Generate keystream block
        keystream_block = hashlib.sha256(key + counter_block).digest()
        
        # Determine slice of data to process
        start = i * 32
        end = min(start + 32, len(data))
        chunk = data[start:end]
        
        # XOR and append
        out.extend(xor_bytes(chunk, keystream_block[:end-start]))
        
    return bytes(out)

# ==========================================
# 2. LSB STEGANOGRAPHY ENCODER / DECODER
# ==========================================
# File structure for encrypted:
# Bytes 0-3:   'STEG' (Magic Bytes)
# Byte  4:     0x01 (Encrypted) or 0x00 (Plaintext)
# Bytes 5-12:  Salt (8 bytes, if encrypted)
# Bytes 13-20: IV/Nonce (8 bytes, if encrypted)
# Bytes 21-24: Payload Length (4 bytes, big-endian)
# Bytes 25+ :  Payload

def embed_bits(img: Image.Image, payload: bytes) -> Image.Image:
    """Embed raw bytes into the LSB of Red, Green, and Blue channels."""
    # Convert image to RGB if not already
    img_rgb = img.convert('RGB')
    pixels = np.array(img_rgb)
    
    # Flatten pixel array for easier LSB modification
    flat_pixels = pixels.flatten()
    
    # Convert payload bytes to a bit array (numpy bool array)
    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    
    if len(payload_bits) > len(flat_pixels):
        raise ValueError(f"Payload too large for this image. Need {len(payload_bits)} bits, but image only has {len(flat_pixels)} LSB slots.")
    
    # Set the LSBs
    # Turn off the lowest bit of flat_pixels in range, then OR with payload bits
    flat_pixels[:len(payload_bits)] = (flat_pixels[:len(payload_bits)] & 0xFE) | payload_bits
    
    # Reshape back to original image dimensions
    new_pixels = flat_pixels.reshape(pixels.shape).astype(np.uint8)
    return Image.fromarray(new_pixels, 'RGB')

def extract_bits(img: Image.Image, num_bits_to_extract: int) -> bytes:
    """Extract a specific number of bits from LSBs of image pixels."""
    img_rgb = img.convert('RGB')
    pixels = np.array(img_rgb)
    flat_pixels = pixels.flatten()
    
    if num_bits_to_extract > len(flat_pixels):
        raise ValueError("Requested bits exceed the capacity of the image.")
    
    # Extract the LSBs
    bits = flat_pixels[:num_bits_to_extract] & 1
    
    # Pack bits back into bytes
    payload_bytes = np.packbits(bits)
    return payload_bytes.tobytes()

def encode_message(img: Image.Image, message: str, password: str = None) -> Image.Image:
    """Encode a secret message into an image, optionally encrypting it."""
    msg_bytes = message.encode('utf-8')
    header = bytearray(b'STEG')
    
    if password:
        # Encrypted path
        header.append(1) # Flag for encrypted
        salt = os.urandom(8)
        iv = os.urandom(8)
        key = derive_key(password, salt)
        ciphertext = aes_ctr_crypt(msg_bytes, key, iv)
        
        header.extend(salt)
        header.extend(iv)
        header.extend(len(ciphertext).to_bytes(4, byteorder='big'))
        payload = bytes(header) + ciphertext
    else:
        # Plaintext path
        header.append(0) # Flag for plaintext
        header.extend(len(msg_bytes).to_bytes(4, byteorder='big'))
        payload = bytes(header) + msg_bytes
        
    return embed_bits(img, payload)

def decode_message(img: Image.Image, password: str = None) -> dict:
    """
    Attempt to extract a hidden message from an image.
    Returns a dictionary containing 'status', 'message', and 'error' if any.
    """
    try:
        # 1. Extract enough bits for the base header (Magic + Flag + Length = 4 + 1 + 4 = 9 bytes = 72 bits)
        # Note: If encrypted, the header is longer, but we can read 25 bytes (200 bits) to cover both cases safely.
        header_bytes_needed = 25
        header_raw = extract_bits(img, header_bytes_needed * 8)
        
        # Check Magic Bytes
        if header_raw[:4] != b'STEG':
            return {
                "status": "error",
                "error": "No StegoEye signature found in this image. It doesn't appear to contain an embedded message."
            }
            
        is_encrypted = header_raw[4] == 1
        
        if is_encrypted:
            salt = header_raw[5:13]
            iv = header_raw[13:21]
            payload_len = int.from_bytes(header_raw[21:25], byteorder='big')
            
            if not password:
                return {
                    "status": "password_required",
                    "message": "This steganography payload is encrypted. Please provide the correct decryption password."
                }
                
            # Extract the actual ciphertext bytes
            total_bits_needed = (25 + payload_len) * 8
            full_payload_raw = extract_bits(img, total_bits_needed)
            ciphertext = full_payload_raw[25:25+payload_len]
            
            # Decrypt
            key = derive_key(password, salt)
            decrypted_bytes = aes_ctr_crypt(ciphertext, key, iv)
            
            try:
                decrypted_text = decrypted_bytes.decode('utf-8')
                return {
                    "status": "success",
                    "message": decrypted_text,
                    "encrypted": True
                }
            except UnicodeDecodeError:
                return {
                    "status": "error",
                    "error": "Decryption failed. The password might be incorrect or the payload is corrupted."
                }
        else:
            # Plaintext path
            payload_len = int.from_bytes(header_raw[5:9], byteorder='big')
            
            total_bits_needed = (9 + payload_len) * 8
            full_payload_raw = extract_bits(img, total_bits_needed)
            plaintext_bytes = full_payload_raw[9:9+payload_len]
            
            try:
                text = plaintext_bytes.decode('utf-8')
                return {
                    "status": "success",
                    "message": text,
                    "encrypted": False
                }
            except UnicodeDecodeError:
                return {
                    "status": "error",
                    "error": "Failed to decode the plaintext message. The payload may be corrupted."
                }
                
    except Exception as e:
        return {
            "status": "error",
            "error": f"An error occurred during extraction: {str(e)}"
        }

# ==========================================
# 3. ADVANCED STEGANALYSIS (DETECTION) ENGINE
# ==========================================
def analyze_metadata(img: Image.Image, raw_bytes: bytes, filename: str) -> dict:
    """Analyze EXIF metadata and look for trailing appended bytes after EOF."""
    metadata = {}
    warnings = []
    
    # A. Format and dimensions
    metadata['filename'] = filename
    metadata['format'] = img.format
    metadata['mode'] = img.mode
    metadata['width'] = img.width
    metadata['height'] = img.height
    metadata['raw_file_size'] = len(raw_bytes)
    
    # Calculate perfect raw pixel size vs file size
    # Raw RGB pixels = width * height * 3
    raw_pixel_size = img.width * img.height * (3 if img.mode == 'RGB' else 4 if img.mode == 'RGBA' else 1)
    metadata['pixel_bytes'] = raw_pixel_size
    
    # B. EXIF Extraction
    exif_data = {}
    if hasattr(img, '_getexif') and img._getexif() is not None:
        raw_exif = img._getexif()
        for tag_id, value in raw_exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                # Clean up bytes
                try:
                    value = value.decode('utf-8', errors='ignore')
                except:
                    value = str(value)
            # Remove giant binaries
            if len(str(value)) < 256:
                exif_data[str(tag)] = value
    metadata['exif'] = exif_data
    
    # C. Trailing Bytes (EOF Appendage Detector)
    trailing_bytes_found = False
    trailing_bytes_len = 0
    trailing_bytes_hex_preview = ""
    trailing_bytes_text_preview = ""
    trailing_bytes_b64 = ""
    
    file_bytes_len = len(raw_bytes)
    
    if img.format == 'PNG':
        # PNG trailer is 'IEND' chunk. Standard PNG ends with `49 45 4E 44 AE 42 60 82`
        iend_marker = b'IEND'
        iend_idx = raw_bytes.rfind(iend_marker)
        if iend_idx != -1:
            # IEND chunk has: 4 bytes length (0), 4 bytes IEND (IEND), 4 bytes CRC
            # Total size of IEND chunk from starts of 'IEND' is 4 ('IEND') + 4 (CRC) = 8 bytes
            iend_end_idx = iend_idx + 8
            if iend_end_idx < file_bytes_len:
                trailing_bytes_found = True
                trailing_data = raw_bytes[iend_end_idx:]
                trailing_bytes_len = len(trailing_data)
                trailing_bytes_hex_preview = trailing_data[:64].hex()
                trailing_bytes_text_preview = trailing_data[:64].decode('utf-8', errors='ignore')
                trailing_bytes_b64 = base64.b64encode(trailing_data).decode('utf-8')
                warnings.append(f"Suspicious trailing data detected! {trailing_bytes_len} bytes found appended after the natural PNG ending (IEND).")
                
    elif img.format == 'JPEG' or img.format == 'MPO':
        # JPEG trailer is `FF D9`
        jpeg_marker = b'\xFF\xD9'
        ffd9_idx = raw_bytes.rfind(jpeg_marker)
        if ffd9_idx != -1:
            ffd9_end_idx = ffd9_idx + 2
            if ffd9_end_idx < file_bytes_len:
                trailing_bytes_found = True
                trailing_data = raw_bytes[ffd9_end_idx:]
                trailing_bytes_len = len(trailing_data)
                trailing_bytes_hex_preview = trailing_data[:64].hex()
                trailing_bytes_text_preview = trailing_data[:64].decode('utf-8', errors='ignore')
                trailing_bytes_b64 = base64.b64encode(trailing_data).decode('utf-8')
                warnings.append(f"Suspicious trailing data detected! {trailing_bytes_len} bytes found appended after the natural JPEG ending (FFD9).")
                
    metadata['trailing_bytes'] = {
        'found': trailing_bytes_found,
        'length': trailing_bytes_len,
        'hex_preview': trailing_bytes_hex_preview,
        'text_preview': trailing_bytes_text_preview,
        'base64': trailing_bytes_b64
    }
    metadata['warnings'] = warnings
    return metadata

def chi2_p_value(chi2: float, df: int) -> float:
    """
    Calculate the statistical p-value for Chi-Square using the Wilson-Hilferty transformation.
    Perfect for pure Python deployment without heavy SciPy package size.
    """
    if df <= 0:
        return 0.0
    if chi2 <= 0:
        return 1.0
        
    try:
        # Wilson-Hilferty approximation for large degrees of freedom (df >= 10)
        # Z = ((chi2 / df)^(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
        term1 = (chi2 / df) ** (1.0 / 3.0)
        term2 = 1.0 - (2.0 / (9.0 * df))
        denom = math.sqrt(2.0 / (9.0 * df))
        Z = (term1 - term2) / denom
        
        # Standard normal CDF approximation (Phi(Z))
        # p-value is the upper tail probability: 1 - Phi(Z)
        p_val = 0.5 * (1.0 - math.erf(Z / math.sqrt(2.0)))
        return p_val
    except Exception:
        # Fallback to general safety if overflow/underflow occurs
        return 0.5

def run_chi_square_steganalysis(img: Image.Image) -> dict:
    """
    Perform a Chi-Square test for LSB steganography on each RGB channel.
    Calculates the probability that LSBs have been randomized (indicating steganography).
    """
    img_rgb = img.convert('RGB')
    pixels = np.array(img_rgb)
    
    channels = ['Red', 'Green', 'Blue']
    results = {}
    overall_stego_prob = 0.0
    
    for idx, name in enumerate(channels):
        channel_pixels = pixels[:, :, idx].flatten()
        
        # Calculate color frequencies (histogram) of the channel
        freqs, _ = np.histogram(channel_pixels, bins=np.arange(257))
        
        # Group frequencies into Pairs of Values (PoVs): {2k, 2k+1}
        chi2_sum = 0.0
        categories_count = 0
        
        for k in range(128):
            y_2k = freqs[2 * k]
            y_2k_plus_1 = freqs[2 * k + 1]
            
            # Expected frequency if LSBs are randomized (equal frequencies)
            x_k = (y_2k + y_2k_plus_1) / 2.0
            
            if x_k > 5: # Threshold to ensure statistics are valid
                chi2_sum += ((y_2k - x_k) ** 2) / x_k
                categories_count += 1
                
        # Degrees of freedom: categories_count - 1
        df = categories_count - 1
        p_value = chi2_p_value(chi2_sum, df)
        
        # In steganalysis:
        # p-value close to 1 means the observed distribution is *identical* to a randomized LSB distribution.
        # Natural images have high variance between adjacent colors, resulting in very high Chi-Square sums (p-value close to 0).
        # Therefore, Stego Probability = 1.0 - p_value is NOT the right way because the p-value represents 
        # the probability that the data is randomized. So a high p-value (~1.0) means high probability of steganography!
        stego_probability = p_value
        
        # If the sample is too uniform or small, protect against false positives
        if len(np.unique(channel_pixels)) < 15:
            stego_probability = 0.0
            
        results[name] = {
            'chi2_stat': float(chi2_sum),
            'df': df,
            'p_value': float(p_value),
            'stego_prob_percent': float(stego_probability * 100)
        }
        
    # Overall score is the maximum probability across channels
    max_prob = max(results['Red']['stego_prob_percent'], 
                  results['Green']['stego_prob_percent'], 
                  results['Blue']['stego_prob_percent'])
    
    return {
        'channels': results,
        'overall_prob_percent': max_prob
    }

def generate_bit_plane_b64(img: Image.Image, channel: str, bit_depth: int = 0) -> str:
    """Generate a base64 encoded PNG of the requested bit plane."""
    img_rgb = img.convert('RGB')
    pixels = np.array(img_rgb)
    
    channel_map = {'Red': 0, 'Green': 1, 'Blue': 2}
    ch_idx = channel_map.get(channel, 0)
    
    # Extract channel
    channel_pixels = pixels[:, :, ch_idx]
    
    # Extract the target bit
    # Right shift by bit_depth and check LSB
    bit_plane = (channel_pixels >> bit_depth) & 1
    
    # Map bit plane 1 -> 255 (white), 0 -> 0 (black)
    visual_plane = (bit_plane * 255).astype(np.uint8)
    
    # Create image
    plane_img = Image.fromarray(visual_plane, mode='L')
    
    # Resize if too large to conserve server bandwidth / client RAM
    if plane_img.width > 800 or plane_img.height > 800:
        plane_img.thumbnail((800, 800))
        
    # Save as PNG to buffer
    buf = io.BytesIO()
    plane_img.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return img_b64

# ==========================================
# 4. FLASK ROUTING AND CONTROLLERS
# ==========================================
@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/encode', methods=['GET', 'POST'])
def encode():
    if request.method == 'POST':
        if 'image' not in request.files or 'message' not in request.form:
            return jsonify({'error': 'Missing required image or message files.'}), 400
            
        file = request.files['image']
        message = request.form['message']
        password = request.form.get('password', '').strip()
        
        if file.filename == '':
            return jsonify({'error': 'No image selected.'}), 400
            
        try:
            img = Image.open(file.stream)
            # Encode
            stego_img = encode_message(img, message, password if password else None)
            
            # Save to bytes
            out_buf = io.BytesIO()
            stego_img.save(out_buf, format='PNG') # Must be PNG for lossless LSB
            out_buf.seek(0)
            
            # Convert to base64 for preview in browser
            img_b64 = base64.b64encode(out_buf.getvalue()).decode('utf-8')
            
            return jsonify({
                'success': True,
                'image_b64': img_b64,
                'filename': f"stego_{os.path.splitext(file.filename)[0]}.png"
            })
        except ValueError as ve:
            return jsonify({'error': str(ve)}), 400
        except Exception as e:
            return jsonify({'error': f"Failed to encode message: {str(e)}"}), 500
            
    return render_template('encode.html')

@app.route('/decode', methods=['GET', 'POST'])
def decode():
    if request.method == 'POST':
        if 'image' not in request.files:
            return jsonify({'error': 'Missing image file.'}), 400
            
        file = request.files['image']
        password = request.form.get('password', '').strip()
        
        if file.filename == '':
            return jsonify({'error': 'No image selected.'}), 400
            
        try:
            img = Image.open(file.stream)
            result = decode_message(img, password if password else None)
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': f"Extraction failed: {str(e)}"}), 500
            
    return render_template('decode.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        if 'image' not in request.files:
            return jsonify({'error': 'Missing image file.'}), 400
            
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({'error': 'No image selected.'}), 400
            
        try:
            # Read raw bytes once to keep a copy for appendage checks
            raw_bytes = file.read()
            file.seek(0) # Reset stream pointer
            
            img = Image.open(file.stream)
            
            # 1. Metadata and Trailer checks
            meta = analyze_metadata(img, raw_bytes, file.filename)
            
            # 2. Chi-Square statistical steganalysis
            chi2_results = run_chi_square_steganalysis(img)
            
            # 3. Generate initial Bit planes (Bit 0 for LSB)
            red_lsb = generate_bit_plane_b64(img, 'Red', 0)
            green_lsb = generate_bit_plane_b64(img, 'Green', 0)
            blue_lsb = generate_bit_plane_b64(img, 'Blue', 0)
            
            # 4. Compute overall threat rating
            # Combination of Chi-Square statistics, trailing bytes detection, etc.
            threat_score = 0
            reasons = []
            
            # A. Chi-Square indicators
            stat_prob = chi2_results['overall_prob_percent']
            if stat_prob > 90:
                threat_score += 45
                reasons.append("Highly suspicious LSB statistical profile (Chi-Square test reports >90% randomized bits).")
            elif stat_prob > 50:
                threat_score += 20
                reasons.append(f"Moderate statistical anomalies detected in LSB distribution ({stat_prob:.1f}% probability).")
                
            # B. Trailing bytes indicator
            if meta['trailing_bytes']['found']:
                threat_score += 50
                reasons.append(f"Suspicious trailing data appended to file end ({meta['trailing_bytes']['length']} extra bytes beyond standard EOF).")
                
            # C. Custom header indicator
            # Let's check if our own custom header signature is there!
            has_sig = False
            try:
                sig_bits = extract_bits(img, 32)
                if sig_bits == b'STEG':
                    has_sig = True
                    threat_score = 100
                    reasons.append("CONFIRMED: Detected valid StegoEye steganography signature!")
            except:
                pass
                
            threat_score = min(threat_score, 100)
            
            if threat_score >= 80:
                severity = "CRITICAL / STEGO DETECTED"
                severity_class = "danger"
            elif threat_score >= 40:
                severity = "HIGH RISK / SUSPICIOUS"
                severity_class = "warning"
            elif threat_score >= 15:
                severity = "LOW RISK / UNLIKELY"
                severity_class = "info"
            else:
                severity = "SAFE / NO SIGNATURE"
                severity_class = "success"
                
            analysis_results = {
                'success': True,
                'metadata': meta,
                'chi2': chi2_results,
                'threat_score': threat_score,
                'severity': severity,
                'severity_class': severity_class,
                'reasons': reasons,
                'bit_planes': {
                    'Red': red_lsb,
                    'Green': green_lsb,
                    'Blue': blue_lsb
                }
            }
            return jsonify(analysis_results)
            
        except Exception as e:
            return jsonify({'error': f"Analysis failed: {str(e)}"}), 500
            
    return render_template('analyze.html')

@app.route('/get_plane', methods=['POST'])
def get_plane():
    """Endpoint to fetch bit planes interactively for selected channel and bit depth."""
    if 'image' not in request.files or 'channel' not in request.form or 'depth' not in request.form:
        return jsonify({'error': 'Missing parameters.'}), 400
        
    file = request.files['image']
    channel = request.form['channel']
    depth = int(request.form['depth'])
    
    try:
        img = Image.open(file.stream)
        img_b64 = generate_bit_plane_b64(img, channel, depth)
        return jsonify({'success': True, 'image_b64': img_b64})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
