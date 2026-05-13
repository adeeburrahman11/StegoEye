# 👁️ StegoEye: Advanced Image Steganography Detection & Security Suite

StegoEye is a professional, high-performance security suite designed for **lossless LSB (Least Significant Bit) steganography encoding/decoding** and **multi-dimensional visual and statistical steganalysis (steganography detection)**.

Built entirely with **Python Flask, Vanilla CSS, and JavaScript**, the system is highly optimized, self-contained, and ready for **100% free hosting** on cloud platforms like Hugging Face Spaces or Render.

---

## ⚡ Key Features

### 1. Lossless Steganography Encoder
*   **Capacity Matrix Analysis:** Automatically calculates the pixel storage capacity of cover images to prevent data overflow.
*   **Custom Cryptosystem:** Uses a secure **salted PBKDF2 key-derivation function** coupled with a pure-Python **SHA256-CTR (Counter Mode) stream cipher** to encrypt messages before injection. No compiled cryptography libraries are required, ensuring fast server-side processing and easy deployments.
*   **Lossless Bit Embedding:** Modifies the lower bits of pixel channels and saves results as PNGs to preserve embedded payloads perfectly.

### 2. Lossless Steganography Decoder
*   **Automatic Header Signature Extraction:** Inspects files for the proprietary `STEG` magic signature.
*   **Interactive Decryption Prompt:** Gracefully identifies password-encrypted payloads and prompts the user to supply the decryption password.

### 3. Advanced Steganalysis (Steganography Detection) Engine
*   **Threat Meter:** Calculates an overall "Threat Score" from 0% (Safe) to 100% (Confirmed Stego) by synthesizing statistical and structural scans.
*   **Wilson-Hilferty Chi-Square Test:** Performs statistical analysis over 128 Pairs of Values (PoVs) on each color channel. If a channel's p-value is close to 1.0, it indicates that pixel color frequencies have been artificially randomized—a mathematical fingerprint of LSB steganography.
*   **EOF Appendage Detector (File Trailer Scanner):** Scans file bytes for data appended *after* the natural image ending markers (`IEND` for PNG, `FFD9` for JPEG).
*   **Appended File Extractor:** Instantly displays previews of appended text and enables downloading of appended binary payloads as `.bin` files.
*   **Interactive Bit-Slicing Visualizer:** Allows users to slide through bit depths 0 (LSB) to 7 (MSB) across Red, Green, and Blue channels. Steganography is immediately exposed as uniform television static against natural silhouettes.

---

## 📂 Project Structure

```text
StegoEye/
├── app.py                  # Core Flask backend containing cryptographic and statistical algorithms
├── requirements.txt        # Python package requirements
├── Dockerfile              # Docker recipe optimized for free hosting environments
├── README.md               # Complete setup, hosting, and technical manual
├── static/
│   ├── css/
│   │   └── style.css       # Premium dark cyberpunk glassmorphism UI stylesheet
│   └── js/
│       └── main.js         # Interactive listeners, SVG gauge controllers, and dynamic AJAX updates
└── templates/
    ├── base.html           # Master layout containing structural grids and background glowing effects
    ├── index.html          # Dynamic welcome dashboard
    ├── encode.html         # Message-hiding dashboard
    ├── decode.html         # Payload extraction deck
    └── analyze.html        # Advanced steganalysis detection terminal
```

---

## 💻 Local Installation & Setup

To run StegoEye locally, ensure you have Python 3.8+ installed, then follow these steps:

1.  **Clone or Navigate to the Directory:**
    ```powershell
    cd d:\Projects\StegoEye
    ```

2.  **Create a Virtual Environment (Optional but Recommended):**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install Dependencies:**
    ```powershell
    pip install -r requirements.txt
    ```

4.  **Launch the Development Server:**
    ```powershell
    python app.py
    ```

5.  **Open the Application:**
    Open your browser and navigate to `http://127.0.0.1:5000` to access the premium terminal interface.

---

## 🚀 Free Hosting Deployment Manual

To host this project completely for free, you can use either **Hugging Face Spaces** or **Render**. The project is pre-configured with a smart `Dockerfile` that adjusts to both systems seamlessly.

### Option A: Hugging Face Spaces (Recommended - 100% Free, Always On)
Hugging Face allows you to host Docker containers for free with excellent performance.

1.  Sign up or log in to [Hugging Face](https://huggingface.co/).
2.  Click on your profile avatar in the top right and select **New Space**.
3.  Fill out the Space details:
    *   **Space Name:** e.g., `stegoeye`
    *   **SDK:** Select **Docker** (This is crucial!).
    *   **Docker Template:** Choose **Blank** (do not select other templates).
    *   **Space License:** Choose `mit` or `apache-2.0`.
    *   **Visibility:** Public.
4.  Once created, click on **Files and versions** tab, then upload the contents of the `StegoEye` directory (you can upload folders directly, or use Git).
    *   *Files to upload:* `app.py`, `requirements.txt`, `Dockerfile`, `static/`, `templates/`.
5.  Hugging Face will automatically detect the `Dockerfile`, build the image, and serve the application on port `7860`. Your steganography detection system is now live and hosted for free!

### Option B: Render Free Tier
Render provides free web service hosting from a GitHub repository.

1.  Push the project code to a public or private repository on **GitHub** or **GitLab**.
2.  Create a free account on [Render](https://render.com/).
3.  In your Render dashboard, click **New +** and select **Web Service**.
4.  Connect your GitHub/GitLab account and select your project repository.
5.  Configure the service details:
    *   **Name:** `stegoeye`
    *   **Region:** Select the closest to you.
    *   **Branch:** `main` (or whichever branch holds your code).
    *   **Runtime:** Select **Docker** (Render will read the `Dockerfile` automatically).
    *   **Plan:** Select the **Free** tier.
6.  Click **Deploy Web Service**.
7.  Render will build the container using our `Dockerfile`. The container will dynamically read Render's ephemeral `$PORT` and bind Gunicorn to it automatically. Your app will be live on a custom `.onrender.com` subdomain for free!

---

## 🔬 Mathematical & Technical Architecture

### 1. Wilson-Hilferty Chi-Square Approximation
For each channel, we calculate:
$$\chi^2 = \sum_{k=0}^{127} \frac{(y_{2k} - y_{2k+1})^2}{2(y_{2k} + y_{2k+1})}$$
Because natural color distributions vary non-randomly while LSB payloads equalize adjacent pairs, a randomized pixel array generates a low $\chi^2$ value, yielding a very high p-value ($p \approx 1.0$). 

To avoid the huge 100MB download footprint of SciPy in free cloud services, we compute the p-value in pure Python using the Wilson-Hilferty Normal distribution transformation:
$$Z = \frac{(\chi^2 / d)^{1/3} - (1 - 2/(9d))}{\sqrt{2/(9d)}}$$
And translate it to standard normal CDF probabilities using the built-in mathematical error function `math.erf()`:
$$P(\text{Stego}) = 0.5 \times \left(1.0 - \text{erf}\left(\frac{Z}{\sqrt{2}}\right)\right)$$

### 2. SHA256-CTR Pure Python Stream Cipher
For secure password encryption, we perform 10,000 rounds of `hashlib.pbkdf2_hmac` with a random 8-byte salt to derive a 256-bit symmetric key. We encrypt the plaintext payload in **Counter Mode (CTR)**:
$$\text{Keystream Block}_i = \text{SHA256}(\text{Derived Key} \mathbin{\Vert} \text{Random IV} \mathbin{\Vert} \text{Block Counter}_i)$$
$$\text{Ciphertext Block}_i = \text{Plaintext Block}_i \oplus \text{Keystream Block}_i$$
This is cryptographically robust, requires no external dependencies like PyCryptodome, and ensures perfect cross-platform compilation reliability.
